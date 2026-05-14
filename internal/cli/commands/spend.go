package commands

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/noeljackson/deepsec/internal/cli"
	"github.com/noeljackson/deepsec/internal/core"
	"github.com/spf13/cobra"
)

// NewSpendCmd aggregates AI cost across runs from each project's
// existing AnalysisHistory. Reader-only: no new tracking required.
func NewSpendCmd(loader func() (*cli.Context, error)) *cobra.Command {
	var projectID, since, by, format string
	cmd := &cobra.Command{
		Use:   "spend",
		Short: "Aggregate AI cost across runs",
		Long: `Aggregate AI cost from AnalysisHistory across one or all projects.

Examples:

  deepsec spend                                 # last 30d, all projects, by agent
  deepsec spend --project-id myproj --since 7d
  deepsec spend --by slug --since 2026-04-01
  deepsec spend --by phase --format json
`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, err := loader()
			if err != nil {
				return err
			}
			cutoff, label, err := resolveSince(since)
			if err != nil {
				return err
			}
			dim, err := parseSpendBy(by)
			if err != nil {
				return err
			}
			fmtKind, err := parseSpendFormat(format)
			if err != nil {
				return err
			}

			projects, err := listProjectsWithData(ctx, projectID)
			if err != nil {
				return err
			}

			agg := newSpendAgg()
			for _, pid := range projects {
				recs, err := ctx.DataRoot.LoadAllFileRecords(pid)
				if err != nil {
					return err
				}
				for _, rec := range recs {
					agg.absorb(rec, cutoff)
				}
			}

			return writeSpend(cmd.OutOrStdout(), agg, dim, fmtKind, label)
		},
	}
	cmd.Flags().StringVar(&projectID, "project-id", "", "Project id (default: all projects)")
	cmd.Flags().StringVar(&since, "since", "30d", "Duration (30d, 7d, 24h) or YYYY-MM-DD; \"all\" disables the cutoff")
	cmd.Flags().StringVar(&by, "by", "agent", "Aggregation dimension: agent, phase, slug, file")
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text, json, csv")
	return cmd
}

type spendDimension string

const (
	spendByAgent spendDimension = "agent"
	spendByPhase spendDimension = "phase"
	spendBySlug  spendDimension = "slug"
	spendByFile  spendDimension = "file"
)

func parseSpendBy(s string) (spendDimension, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "agent", "":
		return spendByAgent, nil
	case "phase":
		return spendByPhase, nil
	case "slug":
		return spendBySlug, nil
	case "file":
		return spendByFile, nil
	}
	return "", fmt.Errorf("--by must be one of: agent, phase, slug, file (got %q)", s)
}

type spendFormat string

const (
	spendFormatText spendFormat = "text"
	spendFormatJSON spendFormat = "json"
	spendFormatCSV  spendFormat = "csv"
)

func parseSpendFormat(s string) (spendFormat, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "text":
		return spendFormatText, nil
	case "json":
		return spendFormatJSON, nil
	case "csv":
		return spendFormatCSV, nil
	}
	return "", fmt.Errorf("--format must be one of: text, json, csv (got %q)", s)
}

// resolveSince accepts "all", a Go duration, "Nd" shorthand, or YYYY-MM-DD.
// Returns the cutoff time (or zero time when no cutoff) and a label for
// the header.
func resolveSince(s string) (time.Time, string, error) {
	now := time.Now().UTC()
	s = strings.TrimSpace(s)
	if s == "" || s == "all" {
		return time.Time{}, "all time", nil
	}
	if d, err := parseDayDuration(s); err == nil {
		return now.Add(-d), fmt.Sprintf("%s → %s", now.Add(-d).Format("2006-01-02"), now.Format("2006-01-02")), nil
	}
	if d, err := time.ParseDuration(s); err == nil {
		return now.Add(-d), fmt.Sprintf("%s → %s", now.Add(-d).Format("2006-01-02"), now.Format("2006-01-02")), nil
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t, fmt.Sprintf("%s → %s", t.Format("2006-01-02"), now.Format("2006-01-02")), nil
	}
	return time.Time{}, "", fmt.Errorf("--since must be \"all\", a duration like 30d / 24h / 90m, or YYYY-MM-DD (got %q)", s)
}

func parseDayDuration(s string) (time.Duration, error) {
	if !strings.HasSuffix(s, "d") {
		return 0, fmt.Errorf("not a day duration")
	}
	n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
	if err != nil || n < 0 {
		return 0, fmt.Errorf("not a day duration")
	}
	return time.Duration(n) * 24 * time.Hour, nil
}

// listProjectsWithData enumerates project ids that have a files/
// directory under DataRoot. When `only` is set, it returns just that id
// (after verifying the directory exists; missing → empty so we render
// an explanatory zero result instead of erroring).
func listProjectsWithData(ctx *cli.Context, only string) ([]string, error) {
	root := string(ctx.DataRoot.Path)
	if only != "" {
		return []string{only}, nil
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		if isNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	out := []string{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(root, e.Name(), "files")); err == nil {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}

func isNotExist(err error) bool {
	var pErr *fs.PathError
	if err == nil {
		return false
	}
	return os.IsNotExist(err) || (err != nil && (pErr != nil))
}

type spendAgg struct {
	totalUSD float64
	entries  int
	runs     map[string]bool
	byAgent  map[string]float64
	byPhase  map[string]float64
	bySlug   map[string]float64
	byFile   map[string]float64
}

func newSpendAgg() *spendAgg {
	return &spendAgg{
		runs:    map[string]bool{},
		byAgent: map[string]float64{},
		byPhase: map[string]float64{},
		bySlug:  map[string]float64{},
		byFile:  map[string]float64{},
	}
}

func (a *spendAgg) absorb(rec *core.FileRecord, cutoff time.Time) {
	slugsByRun := slugsByRunID(rec)
	for _, e := range rec.AnalysisHistory {
		if e.CostUSD == nil {
			continue
		}
		if !cutoff.IsZero() {
			t, err := time.Parse(time.RFC3339Nano, e.InvestigatedAt)
			if err != nil {
				t, err = time.Parse(time.RFC3339, e.InvestigatedAt)
				if err != nil {
					continue
				}
			}
			if t.Before(cutoff) {
				continue
			}
		}
		cost := *e.CostUSD
		a.totalUSD += cost
		a.entries++
		if e.RunID != "" {
			a.runs[e.RunID] = true
		}
		a.byAgent[spendKey(e.AgentType)] += cost
		a.byPhase[spendKey(string(e.Phase))] += cost
		a.byFile[rec.FilePath] += cost
		slugs := slugsByRun[e.RunID]
		if len(slugs) == 0 {
			a.bySlug["(no findings)"] += cost
			continue
		}
		share := cost / float64(len(slugs))
		for _, s := range slugs {
			a.bySlug[s] += share
		}
	}
}

func slugsByRunID(rec *core.FileRecord) map[string][]string {
	out := map[string]map[string]bool{}
	for _, f := range rec.Findings {
		if f.ProducedByRunID == "" {
			continue
		}
		set, ok := out[f.ProducedByRunID]
		if !ok {
			set = map[string]bool{}
			out[f.ProducedByRunID] = set
		}
		set[f.VulnSlug] = true
	}
	flat := map[string][]string{}
	for runID, set := range out {
		s := make([]string, 0, len(set))
		for k := range set {
			s = append(s, k)
		}
		sort.Strings(s)
		flat[runID] = s
	}
	return flat
}

func spendKey(s string) string {
	if strings.TrimSpace(s) == "" {
		return "(unknown)"
	}
	return s
}

type spendRow struct {
	Key  string  `json:"key"`
	USD  float64 `json:"usd"`
	Pct  float64 `json:"pct"`
	rank int
}

func (a *spendAgg) rows(dim spendDimension) []spendRow {
	var src map[string]float64
	switch dim {
	case spendByAgent:
		src = a.byAgent
	case spendByPhase:
		src = a.byPhase
	case spendBySlug:
		src = a.bySlug
	case spendByFile:
		src = a.byFile
	}
	rows := make([]spendRow, 0, len(src))
	for k, v := range src {
		pct := 0.0
		if a.totalUSD > 0 {
			pct = v / a.totalUSD * 100
		}
		rows = append(rows, spendRow{Key: k, USD: v, Pct: pct})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].USD != rows[j].USD {
			return rows[i].USD > rows[j].USD
		}
		return rows[i].Key < rows[j].Key
	})
	for i := range rows {
		rows[i].rank = i
	}
	return rows
}

func writeSpend(w interface{ Write([]byte) (int, error) }, a *spendAgg, dim spendDimension, fmtKind spendFormat, periodLabel string) error {
	rows := a.rows(dim)
	switch fmtKind {
	case spendFormatJSON:
		body := map[string]any{
			"period":    periodLabel,
			"total":     a.totalUSD,
			"runs":      len(a.runs),
			"entries":   a.entries,
			"dimension": string(dim),
			"rows":      rows,
		}
		b, err := json.MarshalIndent(body, "", "  ")
		if err != nil {
			return err
		}
		_, err = w.Write(append(b, '\n'))
		return err
	case spendFormatCSV:
		c := csv.NewWriter(asWriter(w))
		_ = c.Write([]string{"key", "usd", "pct"})
		for _, r := range rows {
			_ = c.Write([]string{r.Key, fmt.Sprintf("%.4f", r.USD), fmt.Sprintf("%.2f", r.Pct)})
		}
		c.Flush()
		return c.Error()
	default:
		var sb strings.Builder
		fmt.Fprintf(&sb, "Period:      %s\n", periodLabel)
		fmt.Fprintf(&sb, "Runs:        %d\n", len(a.runs))
		fmt.Fprintf(&sb, "Entries:     %d\n", a.entries)
		fmt.Fprintf(&sb, "Total cost:  $%.2f\n", a.totalUSD)
		fmt.Fprintf(&sb, "\nby %s:\n", dim)
		if len(rows) == 0 {
			fmt.Fprintln(&sb, "  (no cost recorded — has investigation run on this project?)")
		}
		for _, r := range rows {
			fmt.Fprintf(&sb, "  %-44s $%7.2f  %5.1f%%\n", truncate(r.Key, 44), r.USD, r.Pct)
		}
		_, err := w.Write([]byte(sb.String()))
		return err
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n < 4 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

type writerShim struct {
	w interface{ Write([]byte) (int, error) }
}

func (s writerShim) Write(p []byte) (int, error) { return s.w.Write(p) }

func asWriter(w interface{ Write([]byte) (int, error) }) writerShim { return writerShim{w} }
