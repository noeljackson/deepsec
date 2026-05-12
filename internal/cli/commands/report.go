package commands

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/noeljackson/deepsec/internal/cli"
	"github.com/noeljackson/deepsec/internal/core"
	"github.com/spf13/cobra"
)

// NewReportCmd writes markdown + JSON + CSV reports.
func NewReportCmd(loader func() (*cli.Context, error)) *cobra.Command {
	var projectID, minSeverity, runID string
	var realOnly bool
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Render a project report (markdown + JSON + CSV)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, err := loader()
			if err != nil {
				return err
			}
			records, err := ctx.DataRoot.LoadAllFileRecords(projectID)
			if err != nil {
				return err
			}
			minSev := core.SeverityLow
			if minSeverity != "" {
				minSev = core.Severity(strings.ToUpper(minSeverity))
				if minSev.Rank() == 0 {
					return fmt.Errorf("unknown severity: %s", minSeverity)
				}
			}
			rows := collectRows(records, minSev, runID, realOnly)
			sort.SliceStable(rows, func(i, j int) bool {
				return rows[i].finding.Severity.Rank() > rows[j].finding.Severity.Rank()
			})

			mdPath, err := ctx.DataRoot.ReportMDPath(projectID, runID)
			if err != nil {
				return err
			}
			jsonPath, err := ctx.DataRoot.ReportJSONPath(projectID, runID)
			if err != nil {
				return err
			}
			csvPath, err := ctx.DataRoot.ReportCSVPath(projectID, runID)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(mdPath), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(mdPath, []byte(renderMarkdown(projectID, rows)), 0o644); err != nil {
				return err
			}
			body, err := renderJSON(rows)
			if err != nil {
				return err
			}
			if err := os.WriteFile(jsonPath, body, 0o644); err != nil {
				return err
			}
			if err := writeCSV(csvPath, rows); err != nil {
				return err
			}
			fmt.Printf("report findings=%d → %s, %s, %s\n",
				len(rows), mdPath, jsonPath, csvPath)
			return nil
		},
	}
	cmd.Flags().StringVar(&projectID, "project-id", "", "Project id (required)")
	_ = cmd.MarkFlagRequired("project-id")
	cmd.Flags().StringVar(&minSeverity, "min-severity", "", "Minimum severity to include")
	cmd.Flags().StringVar(&runID, "run-id", "", "Only include findings produced by this run")
	cmd.Flags().BoolVar(&realOnly, "real-only", false, "Drop FP/Fixed findings")
	return cmd
}

type row struct {
	path    string
	record  *core.FileRecord
	finding *core.Finding
}

func collectRows(records []*core.FileRecord, minSev core.Severity, runID string, realOnly bool) []row {
	var rows []row
	for _, rec := range records {
		for i := range rec.Findings {
			f := &rec.Findings[i]
			if f.Severity.Rank() < minSev.Rank() {
				continue
			}
			if runID != "" && f.ProducedByRunID != runID {
				continue
			}
			if realOnly && f.Revalidation != nil {
				v := f.Revalidation.Verdict
				if v == core.VerdictFalsePositive || v == core.VerdictFixed {
					continue
				}
			}
			rows = append(rows, row{path: rec.FilePath, record: rec, finding: f})
		}
	}
	return rows
}

func renderMarkdown(projectID string, rows []row) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# deepsec report — %s\n\n", projectID)
	fmt.Fprintf(&b, "Total findings: %d\n\n", len(rows))
	for _, r := range rows {
		f := r.finding
		fmt.Fprintf(&b, "## [%s] %s — `%s`\n", f.Severity, f.Title, f.VulnSlug)
		fmt.Fprintf(&b, "- file: `%s`\n", r.path)
		fmt.Fprintf(&b, "- lines: %v\n", f.LineNumbers)
		fmt.Fprintf(&b, "- confidence: %s\n", f.Confidence)
		if f.Revalidation != nil {
			fmt.Fprintf(&b, "- revalidation: %s\n", f.Revalidation.Verdict)
		}
		if f.Triage != nil {
			fmt.Fprintf(&b, "- triage: priority=%s exploitability=%s impact=%s\n",
				f.Triage.Priority, f.Triage.Exploitability, f.Triage.Impact)
		}
		fmt.Fprintf(&b, "\n%s\n\n", f.Description)
		fmt.Fprintf(&b, "**Fix:** %s\n\n", f.Recommendation)
	}
	return b.String()
}

func renderJSON(rows []row) ([]byte, error) {
	type payload struct {
		FilePath string        `json:"filePath"`
		Finding  *core.Finding `json:"finding"`
	}
	out := make([]payload, 0, len(rows))
	for _, r := range rows {
		out = append(out, payload{FilePath: r.path, Finding: r.finding})
	}
	return json.MarshalIndent(out, "", "  ")
}

func writeCSV(path string, rows []row) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	_ = w.Write([]string{"file", "severity", "slug", "lines", "title", "confidence", "verdict"})
	for _, r := range rows {
		lines := make([]string, 0, len(r.finding.LineNumbers))
		for _, n := range r.finding.LineNumbers {
			lines = append(lines, strconv.Itoa(n))
		}
		verdict := ""
		if r.finding.Revalidation != nil {
			verdict = string(r.finding.Revalidation.Verdict)
		}
		_ = w.Write([]string{
			r.path,
			string(r.finding.Severity),
			r.finding.VulnSlug,
			strings.Join(lines, ";"),
			r.finding.Title,
			string(r.finding.Confidence),
			verdict,
		})
	}
	return nil
}
