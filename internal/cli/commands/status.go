package commands

import (
	"fmt"

	"github.com/noeljackson/deepsec/internal/cli"
	"github.com/noeljackson/deepsec/internal/core"
	"github.com/spf13/cobra"
)

// NewStatusCmd prints a per-project summary.
func NewStatusCmd(loader func() (*cli.Context, error)) *cobra.Command {
	var projectID string
	var recent int
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show pending/analyzed counts and recent runs",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, err := loader()
			if err != nil {
				return err
			}
			records, err := ctx.DataRoot.LoadAllFileRecords(projectID)
			if err != nil {
				return err
			}
			var pending, analyzed, processing, errored, candidates, findings int
			for _, r := range records {
				switch r.Status {
				case core.StatusPending:
					pending++
				case core.StatusAnalyzed:
					analyzed++
				case core.StatusProcessing:
					processing++
				case core.StatusError:
					errored++
				}
				candidates += len(r.Candidates)
				findings += len(r.Findings)
			}
			fmt.Printf("project %s\n", projectID)
			fmt.Printf("  records:    %d\n", len(records))
			fmt.Printf("  pending:    %d\n", pending)
			fmt.Printf("  analyzed:   %d\n", analyzed)
			fmt.Printf("  processing: %d\n", processing)
			fmt.Printf("  error:      %d\n", errored)
			fmt.Printf("  candidates: %d\n", candidates)
			fmt.Printf("  findings:   %d\n", findings)

			runs, err := ctx.DataRoot.ListRuns(projectID)
			if err != nil {
				return err
			}
			if len(runs) > 0 {
				fmt.Println("\nrecent runs")
				lim := recent
				if lim > len(runs) {
					lim = len(runs)
				}
				for _, r := range runs[:lim] {
					var c, f int
					if r.Stats.CandidatesFound != nil {
						c = *r.Stats.CandidatesFound
					}
					if r.Stats.FindingsCount != nil {
						f = *r.Stats.FindingsCount
					}
					fmt.Printf("  %s [%s/%s] candidates=%d findings=%d\n",
						r.RunID, r.Type, r.Phase, c, f)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&projectID, "project-id", "", "Project id (required)")
	_ = cmd.MarkFlagRequired("project-id")
	cmd.Flags().IntVar(&recent, "recent", 5, "Show last N runs")
	return cmd
}
