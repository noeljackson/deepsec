package commands

import (
	"fmt"
	"sort"
	"strings"

	"github.com/noeljackson/deepsec/internal/cli"
	"github.com/noeljackson/deepsec/internal/core"
	"github.com/spf13/cobra"
)

// NewPrCommentCmd renders markdown for net-new findings from one run.
func NewPrCommentCmd(loader func() (*cli.Context, error)) *cobra.Command {
	var projectID, runID, output string
	var realOnly, skipEmpty bool
	cmd := &cobra.Command{
		Use:   "pr-comment",
		Short: "Render markdown for net-new findings from one process run",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, err := loader()
			if err != nil {
				return err
			}
			if runID == "" {
				runs, err := ctx.DataRoot.ListRuns(projectID)
				if err != nil {
					return err
				}
				for _, r := range runs {
					if r.Type == core.RunTypeProcess {
						runID = r.RunID
						break
					}
				}
				if runID == "" {
					return fmt.Errorf("no recent process run found")
				}
			}

			records, err := ctx.DataRoot.LoadAllFileRecords(projectID)
			if err != nil {
				return err
			}
			var rows []prCommentEntry
			for _, rec := range records {
				for i := range rec.Findings {
					f := &rec.Findings[i]
					if f.ProducedByRunID != runID {
						continue
					}
					if realOnly && f.Revalidation != nil {
						v := f.Revalidation.Verdict
						if v == core.VerdictFalsePositive || v == core.VerdictFixed {
							continue
						}
					}
					rows = append(rows, prCommentEntry{path: rec.FilePath, finding: f})
				}
			}
			if len(rows) == 0 && skipEmpty {
				return nil
			}
			sort.SliceStable(rows, func(i, j int) bool {
				return rows[i].finding.Severity.Rank() > rows[j].finding.Severity.Rank()
			})

			body := renderPRComment(runID, rows)
			if output == "" {
				fmt.Println(body)
				return nil
			}
			return writePrivateFile(output, []byte(body))
		},
	}
	cmd.Flags().StringVar(&projectID, "project-id", "", "Project id (required)")
	_ = cmd.MarkFlagRequired("project-id")
	cmd.Flags().StringVar(&runID, "run-id", "", "Run to filter by (default: most recent process run)")
	cmd.Flags().BoolVar(&realOnly, "real-only", true, "Drop FP/Fixed findings")
	cmd.Flags().BoolVar(&skipEmpty, "skip-empty", false, "Output nothing when there are no net-new findings")
	cmd.Flags().StringVar(&output, "output", "", "Write to this path (default: stdout)")
	return cmd
}

type prCommentEntry struct {
	path    string
	finding *core.Finding
}

func renderPRComment(runID string, rows []prCommentEntry) string {
	var b strings.Builder
	if len(rows) == 0 {
		fmt.Fprintf(&b, "## deepsec — no net-new findings for run `%s` :white_check_mark:\n", runID)
		return b.String()
	}
	by := map[core.Severity]int{}
	for _, r := range rows {
		by[r.finding.Severity]++
	}
	plural := ""
	if len(rows) != 1 {
		plural = "s"
	}
	fmt.Fprintf(&b, "## deepsec — %d net-new finding%s for run `%s`\n", len(rows), plural, runID)
	parts := []string{}
	for _, sev := range []core.Severity{core.SeverityCritical, core.SeverityHigh, core.SeverityHighBug, core.SeverityMedium, core.SeverityBug, core.SeverityLow} {
		if n, ok := by[sev]; ok {
			parts = append(parts, fmt.Sprintf("%d × %s", n, sev))
		}
	}
	fmt.Fprintf(&b, "%s\n\n", strings.Join(parts, " · "))
	for _, r := range rows {
		f := r.finding
		fmt.Fprintf(&b, "### `%s` — %s **%s**\n", sevBadge(f.Severity), f.Severity, f.Title)
		fmt.Fprintf(&b, "- file: `%s` (lines %v)\n", r.path, f.LineNumbers)
		fmt.Fprintf(&b, "- slug: `%s`\n", f.VulnSlug)
		fmt.Fprintf(&b, "- confidence: `%s`\n", f.Confidence)
		if f.Revalidation != nil {
			fmt.Fprintf(&b, "- revalidation: `%s`\n", f.Revalidation.Verdict)
		}
		fmt.Fprintf(&b, "\n%s\n\n", f.Description)
		fmt.Fprintf(&b, "**Fix:** %s\n\n", f.Recommendation)
	}
	return b.String()
}

func sevBadge(s core.Severity) string {
	switch s {
	case core.SeverityCritical:
		return "CRIT"
	case core.SeverityHigh, core.SeverityHighBug:
		return "HIGH"
	case core.SeverityMedium:
		return "MED "
	case core.SeverityBug:
		return "BUG "
	}
	return "LOW "
}
