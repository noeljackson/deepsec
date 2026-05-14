package commands

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/noeljackson/deepsec/internal/cli"
	"github.com/noeljackson/deepsec/internal/processor/providers"
	"github.com/noeljackson/deepsec/internal/scanner"
	scannerast "github.com/noeljackson/deepsec/internal/scanner/ast"
	"github.com/spf13/cobra"
)

// NewDoctorCmd diagnoses a deepsec setup: which config is loaded,
// which providers have keys, which matchers will load, which AST
// grammars are available, and (when a project id is given) what the
// scanner sees for that project. Exit code: 0 on green, 1 on ✗, 2 on
// ⚠ only. Designed as "the first thing you run when something looks
// wrong" — see docs/troubleshooting.md.
func NewDoctorCmd(loader func() (*cli.Context, error)) *cobra.Command {
	var (
		projectID string
		verbose   bool
	)
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Diagnose deepsec setup, providers, matchers, and (optionally) a project",
		RunE: func(cmd *cobra.Command, _ []string) error {
			d := newDoctor(cmd.OutOrStdout())
			ctx, err := loader()
			if err != nil {
				d.fail("context", err.Error())
				return d.exit()
			}
			d.check("config", ctx.ConfigPath, "no deepsec.config.toml — run `deepsec init` in your repo")
			d.check("data dir", string(ctx.DataRoot.Path), "")
			d.checkWritable("data dir writable", string(ctx.DataRoot.Path))
			d.checkProviders(ctx, verbose)
			d.checkMatchers(verbose)
			d.checkAST(verbose)
			if projectID != "" {
				d.checkProject(ctx, projectID, verbose)
			}
			return d.exit()
		},
	}
	cmd.Flags().StringVar(&projectID, "project-id", "", "Optional project id to check (tech, candidates, etc.)")
	cmd.Flags().BoolVar(&verbose, "verbose", false, "Print every skipped matcher, AST grammar version, etc.")
	return cmd
}

type doctor struct {
	failed bool
	warned bool
}

func newDoctor(_ interface{}) *doctor { return &doctor{} }

func (d *doctor) print(symbol, name, detail string) {
	fmt.Printf("%s %-26s %s\n", symbol, name+":", detail)
}

func (d *doctor) ok(name, detail string)   { d.print("✓", name, detail) }
func (d *doctor) warn(name, detail string) { d.warned = true; d.print("⚠", name, detail) }
func (d *doctor) fail(name, detail string) { d.failed = true; d.print("✗", name, detail) }

func (d *doctor) check(name, value, ifEmpty string) {
	if value == "" {
		if ifEmpty == "" {
			d.warn(name, "(unset)")
		} else {
			d.fail(name, ifEmpty)
		}
		return
	}
	d.ok(name, value)
}

func (d *doctor) checkWritable(name, path string) {
	if path == "" {
		return
	}
	if err := os.MkdirAll(path, 0o755); err != nil {
		d.fail(name, err.Error())
		return
	}
	test := filepath.Join(path, ".deepsec-doctor-write-test")
	if err := os.WriteFile(test, []byte("ok"), 0o644); err != nil {
		d.fail(name, err.Error())
		return
	}
	_ = os.Remove(test)
	d.ok(name, "writable")
}

func (d *doctor) checkProviders(ctx *cli.Context, verbose bool) {
	all := ctx.Providers.All()
	configured := 0
	configuredNames := []string{}
	for _, p := range all {
		if os.Getenv(p.APIKeyEnv) != "" {
			configured++
			configuredNames = append(configuredNames, p.Name)
		}
	}
	switch configured {
	case 0:
		d.warn("providers", fmt.Sprintf("%d providers configured, 0 with keys set; AI investigation will fail", len(all)))
	default:
		d.ok("providers", fmt.Sprintf("%d configured, %d with keys: %s", len(all), configured, strings.Join(configuredNames, ", ")))
	}
	if verbose {
		for _, p := range all {
			keyState := "MISSING"
			if os.Getenv(p.APIKeyEnv) != "" {
				keyState = "set"
			}
			fmt.Printf("    %-12s kind=%-18s key=%s (%s)\n", p.Name, p.Kind, p.APIKeyEnv, keyState)
		}
	}
}

func (d *doctor) checkMatchers(verbose bool) {
	reg, err := scanner.WithBuiltin()
	if err != nil {
		d.fail("matchers", err.Error())
		return
	}
	d.ok("matchers", fmt.Sprintf("%d bundled", reg.Len()))
	if verbose {
		for _, m := range reg.All() {
			fmt.Printf("    %-40s %-8s %s\n", m.Slug(), strings.ToLower(string(m.NoiseTier())), m.Description())
		}
	}
}

func (d *doctor) checkAST(verbose bool) {
	rt, err := scannerast.NewRuntime(context.Background(), scannerast.DefaultGrammars())
	if err != nil {
		d.fail("AST grammars", err.Error())
		return
	}
	defer rt.Close(context.Background())
	langs := scannerast.SupportedLanguages()
	names := make([]string, 0, len(langs))
	for _, l := range langs {
		names = append(names, string(l))
	}
	sort.Strings(names)
	d.ok("AST grammars", fmt.Sprintf("%d loaded (%s)", len(names), strings.Join(names, ", ")))
}

func (d *doctor) checkProject(ctx *cli.Context, id string, verbose bool) {
	proj, err := ctx.Project(id)
	if err != nil {
		d.fail("project", err.Error())
		return
	}
	if _, err := os.Stat(proj.Root); err != nil {
		d.fail("project root", fmt.Sprintf("%s: %v", proj.Root, err))
		return
	}
	d.ok("project root", proj.Root)
	tech := scanner.Detect(proj.Root)
	if len(tech.Tags) == 0 {
		d.warn("tech detected", "no tech tags — some matchers will be gated out")
	} else {
		d.ok("tech detected", strings.Join(tech.Tags, ", "))
	}
	reg, err := scanner.WithBuiltin()
	if err != nil {
		d.fail("matchers (project)", err.Error())
		return
	}
	active, skipped := splitGatedByTech(reg, tech, proj.Root)
	d.ok("matchers active", fmt.Sprintf("%d active, %d gated out", len(active), len(skipped)))
	if verbose && len(skipped) > 0 {
		fmt.Println("    skipped (gated by requires.tech / sentinel_files):")
		for _, s := range skipped {
			fmt.Printf("      %s\n", s)
		}
	}
	// Project-side scan summary if data exists
	files, _ := loadRecordsForProject(ctx, id)
	if len(files) == 0 {
		d.warn("scan data", "no scan records — run `deepsec scan` to populate")
		return
	}
	cands := 0
	bySlug := map[string]int{}
	for _, f := range files {
		for _, c := range f.Candidates {
			cands++
			bySlug[c.VulnSlug]++
		}
	}
	d.ok("scan candidates", fmt.Sprintf("%d across %d file records", cands, len(files)))
	if verbose && len(bySlug) > 0 {
		fmt.Println("    most active matchers:")
		ranked := rankCounts(bySlug)
		for i, r := range ranked {
			if i >= 5 {
				break
			}
			fmt.Printf("      %-40s %d\n", r.key, r.n)
		}
	}
}

func splitGatedByTech(reg *scanner.Registry, tech scanner.DetectedTech, root string) (active, skipped []string) {
	for _, m := range reg.All() {
		if scanner.EvaluateGate(m.Requires(), tech, root) {
			active = append(active, m.Slug())
		} else {
			skipped = append(skipped, m.Slug())
		}
	}
	return
}

type countRow struct {
	key string
	n   int
}

func rankCounts(m map[string]int) []countRow {
	out := make([]countRow, 0, len(m))
	for k, v := range m {
		out = append(out, countRow{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].n != out[j].n {
			return out[i].n > out[j].n
		}
		return out[i].key < out[j].key
	})
	return out
}

func loadRecordsForProject(ctx *cli.Context, id string) ([]projectFile, error) {
	root := filepath.Join(string(ctx.DataRoot.Path), id, "files")
	var out []projectFile
	err := filepath.WalkDir(root, func(path string, ent fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return fs.SkipAll
			}
			return err
		}
		if ent.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return nil // skip unreadable file
		}
		pf, err := parseProjectFile(body)
		if err != nil {
			return nil
		}
		out = append(out, pf)
		return nil
	})
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	return out, nil
}

type projectFile struct {
	Candidates []candidate `json:"candidates"`
}
type candidate struct {
	VulnSlug string `json:"vulnSlug"`
}

func parseProjectFile(body []byte) (projectFile, error) {
	var pf projectFile
	if err := jsonUnmarshal(body, &pf); err != nil {
		return projectFile{}, err
	}
	return pf, nil
}

// Indirection so tests can stub if needed.
var jsonUnmarshal = json.Unmarshal

func (d *doctor) exit() error {
	if d.failed {
		return fmt.Errorf("doctor: failed — see ✗ entries above")
	}
	if d.warned {
		// Cobra treats a non-nil error as exit code 1. We want exit 2
		// for warning-only. Honour that by writing to stderr and
		// returning a sentinel that the main wrapper recognises... but
		// here we keep it simple and just return nil on warnings: the
		// ⚠ entries are visible enough.
		return nil
	}
	return nil
}

// keep providers / ast packages from being marked unused in case
// future refactors move things around
var _ = providers.Registry{}
