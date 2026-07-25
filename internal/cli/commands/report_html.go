package commands

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"path/filepath"
	"sort"
	"strings"

	"github.com/noeljackson/deepsec/internal/core"
)

//go:embed report_html_assets/index.html.tmpl
var htmlIndexTemplate string

//go:embed report_html_assets/finding.html.tmpl
var htmlFindingTemplate string

//go:embed report_html_assets/style.css
var htmlStyleCSS string

// runHTMLReport renders a self-contained static site at `output`. The
// site has no JS dependencies and no server requirements — just
// `index.html` + `findings/<id>.html` + `style.css`. Suitable for
// dropping in S3, GH Pages, or any static host.
func runHTMLReport(projectID string, records []*core.FileRecord, minSev core.Severity, runID string, realOnly bool, output string) error {
	if projectID == "" {
		return fmt.Errorf("--project-id is required for html reports")
	}
	if output == "" {
		return fmt.Errorf("--output is required for html reports (path to write the static site)")
	}
	rows := collectRows(records, minSev, runID, realOnly)
	sort.SliceStable(rows, func(i, j int) bool {
		ri, rj := rows[i].finding.Severity.Rank(), rows[j].finding.Severity.Rank()
		if ri != rj {
			return ri > rj
		}
		return rows[i].path < rows[j].path
	})
	if err := ensurePrivateDir(output); err != nil {
		return err
	}
	if err := ensurePrivateDir(filepath.Join(output, "findings")); err != nil {
		return err
	}
	if err := writePrivateFile(filepath.Join(output, "style.css"), []byte(htmlStyleCSS)); err != nil {
		return err
	}
	entries := make([]htmlEntry, 0, len(rows))
	for _, r := range rows {
		entries = append(entries, toHTMLEntry(r))
	}
	indexTmpl, err := template.New("index").Funcs(htmlFuncs()).Parse(htmlIndexTemplate)
	if err != nil {
		return fmt.Errorf("parse index template: %w", err)
	}
	findingTmpl, err := template.New("finding").Funcs(htmlFuncs()).Parse(htmlFindingTemplate)
	if err != nil {
		return fmt.Errorf("parse finding template: %w", err)
	}
	var index strings.Builder
	if err := indexTmpl.Execute(&index, indexData{
		ProjectID:     projectID,
		TotalFindings: len(entries),
		Entries:       entries,
		Counts:        severityCounts(entries),
	}); err != nil {
		return err
	}
	if err := writePrivateFile(filepath.Join(output, "index.html"), []byte(index.String())); err != nil {
		return err
	}
	for _, e := range entries {
		path := filepath.Join(output, "findings", e.ID+".html")
		if err := writeFindingPage(findingTmpl, path, projectID, e); err != nil {
			return err
		}
	}
	fmt.Printf("html report findings=%d → %s\n", len(entries), filepath.Join(output, "index.html"))
	return nil
}

func writeFindingPage(tmpl *template.Template, path, projectID string, e htmlEntry) error {
	var body strings.Builder
	if err := tmpl.Execute(&body, findingData{ProjectID: projectID, Entry: e}); err != nil {
		return err
	}
	return writePrivateFile(path, []byte(body.String()))
}

type htmlEntry struct {
	ID             string
	Path           string
	Severity       string
	SeverityRank   int
	SeverityClass  string
	Slug           string
	Title          string
	Description    string
	Recommendation string
	Lines          string
	Confidence     string
	Verdict        string
	Priority       string
}

type indexData struct {
	ProjectID     string
	TotalFindings int
	Entries       []htmlEntry
	Counts        []severityCount
}

type findingData struct {
	ProjectID string
	Entry     htmlEntry
}

type severityCount struct {
	Severity string
	Count    int
}

func toHTMLEntry(r row) htmlEntry {
	f := r.finding
	lines := make([]string, 0, len(f.LineNumbers))
	for _, n := range f.LineNumbers {
		lines = append(lines, fmt.Sprintf("%d", n))
	}
	verdict := ""
	if f.Revalidation != nil {
		verdict = string(f.Revalidation.Verdict)
	}
	priority := ""
	if f.Triage != nil {
		priority = string(f.Triage.Priority)
	}
	id := findingHTMLID(r.path, f)
	sev := strings.ToUpper(string(f.Severity))
	return htmlEntry{
		ID:             id,
		Path:           r.path,
		Severity:       sev,
		SeverityRank:   f.Severity.Rank(),
		SeverityClass:  "sev-" + strings.ToLower(sev),
		Slug:           f.VulnSlug,
		Title:          f.Title,
		Description:    f.Description,
		Recommendation: f.Recommendation,
		Lines:          strings.Join(lines, ", "),
		Confidence:     string(f.Confidence),
		Verdict:        verdict,
		Priority:       priority,
	}
}

func findingHTMLID(path string, f *core.Finding) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%s\x00%s", path, f.VulnSlug, f.Title)
	for _, n := range f.LineNumbers {
		fmt.Fprintf(h, "\x00%d", n)
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func severityCounts(entries []htmlEntry) []severityCount {
	counts := map[string]int{}
	for _, e := range entries {
		counts[e.Severity]++
	}
	order := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"}
	out := make([]severityCount, 0, len(order))
	for _, sev := range order {
		if n, ok := counts[sev]; ok {
			out = append(out, severityCount{Severity: sev, Count: n})
		}
	}
	return out
}

func htmlFuncs() template.FuncMap {
	return template.FuncMap{
		"json": func(v any) (template.JS, error) {
			b, err := json.Marshal(v)
			if err != nil {
				return "", err
			}
			return template.JS(b), nil
		},
	}
}
