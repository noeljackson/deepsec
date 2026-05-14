// Command codex-recall-feed is a one-shot experiment driver that
// reads a Codex Cyber CSV export, filters to vuln classes where
// deepsec has genuine recall gaps (not intentional-design noise),
// clusters them by class, and asks ProposeNewMatcher to draft a
// bundled-matcher TOML block per cluster.
//
// The output proposals land under data/codex-recall-proposals/ as
// `<class>.json` for review. They are NOT auto-applied — the
// human filter is: is this category actually worth a bundled
// matcher, and does the proposed TOML look right.
//
// Usage:
//
//	ZAI_API_KEY=... go run ./cmd/codex-recall-feed \
//	  --csv /path/to/codex-security-findings-*.csv \
//	  --project-root /path/to/scanned/repo \
//	  --classes auth-flow,open-redirect \
//	  --agent zai-coding
package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/noeljackson/deepsec/internal/processor"
	"github.com/noeljackson/deepsec/internal/processor/providers"
	"github.com/noeljackson/deepsec/internal/scanner"
)

func main() {
	var csvPath, projectRoot, classesCSV, agentName, modelOverride, outDir string
	var perClusterCap int
	flag.StringVar(&csvPath, "csv", "", "Codex CSV export path (required)")
	flag.StringVar(&projectRoot, "project-root", "", "Local checkout of the scanned repo (for path validation)")
	flag.StringVar(&classesCSV, "classes", "auth-flow,open-redirect", "Comma-separated vuln classes to propose matchers for")
	flag.StringVar(&agentName, "agent", "zai-coding", "Provider profile name")
	flag.StringVar(&modelOverride, "model", "", "Override the backend model")
	flag.StringVar(&outDir, "out", "data/codex-recall-proposals", "Where to write the proposal JSON files")
	flag.IntVar(&perClusterCap, "max-fns-per-cluster", 8, "Max false-negative samples per cluster")
	flag.Parse()

	if csvPath == "" {
		fmt.Fprintln(os.Stderr, "--csv is required")
		os.Exit(2)
	}
	classes := splitCSV(classesCSV)
	if len(classes) == 0 {
		fmt.Fprintln(os.Stderr, "--classes is required")
		os.Exit(2)
	}

	rows, err := readCodexCSV(csvPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read csv: %v\n", err)
		os.Exit(1)
	}
	clusters := clusterByClass(rows, classes, perClusterCap, projectRoot)
	if len(clusters) == 0 {
		fmt.Fprintln(os.Stderr, "no clusters matched the requested classes")
		os.Exit(1)
	}

	backend, err := newBackend(agentName, modelOverride)
	if err != nil {
		fmt.Fprintf(os.Stderr, "build backend: %v\n", err)
		os.Exit(1)
	}

	reg, err := scanner.WithBuiltin()
	if err != nil {
		fmt.Fprintf(os.Stderr, "load matchers: %v\n", err)
		os.Exit(1)
	}
	existing := reg.Slugs()

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir %s: %v\n", outDir, err)
		os.Exit(1)
	}

	for _, c := range clusters {
		fmt.Printf("=== cluster %s (%d FNs) ===\n", c.VulnSlug, len(c.FalseNegatives))
		out, err := processor.ProposeNewMatcher(context.Background(), backend, c, existing)
		if err != nil {
			fmt.Fprintf(os.Stderr, "propose %s: %v\n", c.VulnSlug, err)
			continue
		}
		fmt.Printf("decision: %s\n", out.Decision)
		if out.Slug != "" {
			fmt.Printf("slug: %s\n", out.Slug)
		}
		if out.Rationale != "" {
			fmt.Printf("rationale: %s\n", out.Rationale)
		}
		path := filepath.Join(outDir, c.VulnSlug+".json")
		body, _ := json.MarshalIndent(out, "", "  ")
		_ = os.WriteFile(path, body, 0o644)
		fmt.Printf("→ saved %s\n\n", path)
	}
}

func newBackend(name, model string) (processor.AgentBackend, error) {
	reg, err := providers.LoadBuiltin()
	if err != nil {
		return nil, err
	}
	profile := reg.Get(name)
	if profile == nil {
		return nil, fmt.Errorf("unknown provider %q", name)
	}
	key, err := reg.LookupKey(name)
	if err != nil {
		return nil, err
	}
	return processor.NewBackend(profile, model, key, processor.ModelSettings{})
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

type codexRow struct {
	URL         string
	Title       string
	Description string
	Severity    string
	Paths       []string
	Class       string
}

func readCodexCSV(path string) ([]codexRow, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := csv.NewReader(f)
	r.LazyQuotes = true
	r.FieldsPerRecord = -1
	header, err := r.Read()
	if err != nil {
		return nil, err
	}
	idx := map[string]int{}
	for i, h := range header {
		idx[h] = i
	}
	var out []codexRow
	for {
		rec, err := r.Read()
		if err != nil {
			break
		}
		paths := []string{}
		for _, p := range strings.Split(rec[idx["relevant_paths"]], " | ") {
			if p = strings.TrimSpace(p); p != "" {
				paths = append(paths, p)
			}
		}
		title := rec[idx["title"]]
		desc := rec[idx["description"]]
		row := codexRow{
			URL:         rec[idx["finding_url"]],
			Title:       title,
			Description: desc,
			Severity:    rec[idx["severity"]],
			Paths:       paths,
			Class:       codexClass(title, desc),
		}
		out = append(out, row)
	}
	return out, nil
}

func codexClass(title, desc string) string {
	t := strings.ToLower(title + " " + desc)
	switch {
	case strings.Contains(t, "sql") && (strings.Contains(t, "inject") || strings.Contains(t, "concat")):
		return "sqli"
	case strings.Contains(t, "command injection") || strings.Contains(t, "shell metacharacter"):
		return "command-injection"
	case strings.Contains(t, "ssrf"):
		return "ssrf"
	case strings.Contains(t, "open redirect") || (strings.Contains(t, "redirect") && strings.Contains(t, "unsafe")):
		return "open-redirect"
	case strings.Contains(t, "xss") || strings.Contains(t, "cross-site script"):
		return "xss"
	case strings.Contains(t, "oauth") || strings.Contains(t, "oidc"):
		return "auth-flow"
	case strings.Contains(t, "csrf"):
		return "csrf"
	case strings.Contains(t, "path traversal"):
		return "path-traversal"
	case strings.Contains(t, "xxe"):
		return "xxe"
	case strings.Contains(t, "deserial"):
		return "deserialize"
	case strings.Contains(t, "race") || strings.Contains(t, "toctou"):
		return "race"
	case strings.Contains(t, "secret") || (strings.Contains(t, "token") && strings.Contains(t, "hardcod")):
		return "hardcoded-secret"
	}
	return "other"
}

func clusterByClass(rows []codexRow, classes []string, cap int, projectRoot string) []processor.RecallCluster {
	wanted := map[string]bool{}
	for _, c := range classes {
		wanted[c] = true
	}
	byClass := map[string][]codexRow{}
	for _, r := range rows {
		if !wanted[r.Class] {
			continue
		}
		if projectRoot != "" && !anyPathExists(projectRoot, r.Paths) {
			continue
		}
		byClass[r.Class] = append(byClass[r.Class], r)
	}
	var out []processor.RecallCluster
	for cls, rs := range byClass {
		sort.Slice(rs, func(i, j int) bool { return severityRank(rs[i].Severity) > severityRank(rs[j].Severity) })
		if len(rs) > cap {
			rs = rs[:cap]
		}
		fns := make([]processor.PatchFalseNegative, 0, len(rs))
		for i, r := range rs {
			fns = append(fns, processor.PatchFalseNegative{
				TaskID:    "codex-external",
				IssueID:   fmt.Sprintf("codex-%d", i),
				File:      pickFile(r.Paths),
				StartLine: 0,
				EndLine:   0,
				VulnSlugs: []string{cls},
				Reason:    fmt.Sprintf("[%s] %s — %s", r.Severity, r.Title, truncate(r.Description, 240)),
			})
		}
		out = append(out, processor.RecallCluster{
			VulnSlug:       cls,
			FalseNegatives: fns,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].VulnSlug < out[j].VulnSlug })
	return out
}

func anyPathExists(root string, paths []string) bool {
	for _, p := range paths {
		if _, err := os.Stat(filepath.Join(root, p)); err == nil {
			return true
		}
	}
	return false
}

func pickFile(paths []string) string {
	if len(paths) > 0 {
		return paths[0]
	}
	return ""
}

func severityRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "informational":
		return 1
	}
	return 0
}

func truncate(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
