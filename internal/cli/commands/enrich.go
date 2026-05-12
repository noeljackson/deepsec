package commands

import (
	"fmt"

	"github.com/noeljackson/deepsec/internal/cli"
	"github.com/noeljackson/deepsec/internal/processor"
	"github.com/spf13/cobra"
)

// NewEnrichCmd runs the git-log enrichment pass.
func NewEnrichCmd(loader func() (*cli.Context, error)) *cobra.Command {
	var projectID, filter string
	var maxCommitters int
	var force bool
	cmd := &cobra.Command{
		Use:   "enrich",
		Short: "Populate FileRecord.gitInfo.recentCommitters via git log",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, err := loader()
			if err != nil {
				return err
			}
			proj, err := ctx.Project(projectID)
			if err != nil {
				return err
			}
			out, err := processor.Enrich(processor.EnrichOptions{
				ProjectID:     projectID,
				ProjectRoot:   proj.Root,
				DataRoot:      ctx.DataRoot,
				FilterPrefix:  filter,
				MaxCommitters: maxCommitters,
				Force:         force,
			})
			if err != nil {
				return err
			}
			fmt.Printf("enrich enriched=%d skipped=%d\n", out.FilesEnriched, out.FilesSkipped)
			return nil
		},
	}
	cmd.Flags().StringVar(&projectID, "project-id", "", "Project id (required)")
	_ = cmd.MarkFlagRequired("project-id")
	cmd.Flags().StringVar(&filter, "filter", "", "Path-prefix filter")
	cmd.Flags().IntVar(&maxCommitters, "max-committers", 5, "Max recent committers per file")
	cmd.Flags().BoolVar(&force, "force", false, "Re-enrich files that already have gitInfo")
	return cmd
}
