package commands

import (
	"fmt"
	"sort"

	"github.com/noeljackson/deepsec/internal/cli"
	"github.com/noeljackson/deepsec/internal/core"
	"github.com/spf13/cobra"
)

// NewMetricsCmd aggregates metrics across all runs.
func NewMetricsCmd(loader func() (*cli.Context, error)) *cobra.Command {
	var projectID string
	cmd := &cobra.Command{
		Use:   "metrics",
		Short: "Aggregate metrics across all runs",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, err := loader()
			if err != nil {
				return err
			}
			records, err := ctx.DataRoot.LoadAllFileRecords(projectID)
			if err != nil {
				return err
			}
			runs, err := ctx.DataRoot.ListRuns(projectID)
			if err != nil {
				return err
			}

			var totalCost float64
			var totalIn, totalOut, totalDur uint64
			for _, r := range runs {
				if r.Stats.TotalCostUSD != nil {
					totalCost += *r.Stats.TotalCostUSD
				}
				if r.Stats.TotalInputTokens != nil {
					totalIn += *r.Stats.TotalInputTokens
				}
				if r.Stats.TotalOutputTokens != nil {
					totalOut += *r.Stats.TotalOutputTokens
				}
				if r.Stats.TotalDurationMs != nil {
					totalDur += *r.Stats.TotalDurationMs
				}
			}

			type slugStats struct{ total, tp, fp int }
			bySlug := map[string]*slugStats{}
			var tp, fp, fixed, uncertain, total int
			for _, rec := range records {
				for _, f := range rec.Findings {
					total++
					s := bySlug[f.VulnSlug]
					if s == nil {
						s = &slugStats{}
						bySlug[f.VulnSlug] = s
					}
					s.total++
					if f.Revalidation != nil {
						switch f.Revalidation.Verdict {
						case core.VerdictTruePositive, core.VerdictAcceptedRisk:
							tp++
							s.tp++
						case core.VerdictFalsePositive:
							fp++
							s.fp++
						case core.VerdictFixed:
							fixed++
						case core.VerdictUncertain:
							uncertain++
						}
					}
				}
			}

			fmt.Println("metrics")
			fmt.Printf("  runs:            %d\n", len(runs))
			fmt.Printf("  total cost:      $%.4f\n", totalCost)
			fmt.Printf("  input tokens:    %d\n", totalIn)
			fmt.Printf("  output tokens:   %d\n", totalOut)
			fmt.Printf("  total runtime:   %.1fs\n", float64(totalDur)/1000.0)
			fmt.Println()
			fmt.Printf("  findings:        %d\n", total)
			fmt.Printf("    TP:            %d\n", tp)
			fmt.Printf("    FP:            %d\n", fp)
			fmt.Printf("    fixed:         %d\n", fixed)
			fmt.Printf("    uncertain:     %d\n", uncertain)
			fmt.Println()
			fmt.Println("  by slug:")
			slugs := make([]string, 0, len(bySlug))
			for s := range bySlug {
				slugs = append(slugs, s)
			}
			sort.Slice(slugs, func(i, j int) bool {
				return bySlug[slugs[i]].total > bySlug[slugs[j]].total
			})
			limit := 30
			if limit > len(slugs) {
				limit = len(slugs)
			}
			for _, slug := range slugs[:limit] {
				s := bySlug[slug]
				fmt.Printf("    %-42s total=%-5d TP=%-4d FP=%-4d\n", slug, s.total, s.tp, s.fp)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&projectID, "project-id", "", "Project id (required)")
	_ = cmd.MarkFlagRequired("project-id")
	return cmd
}
