package commands

import (
	"fmt"

	"github.com/noeljackson/deepsec/internal/cli"
	"github.com/spf13/cobra"
)

// NewInitProjectCmd writes `data/<id>/project.json` for a new project.
func NewInitProjectCmd(loader func() (*cli.Context, error)) *cobra.Command {
	var projectID, root, githubURL string
	cmd := &cobra.Command{
		Use:   "init-project",
		Short: "Initialize a new project entry in `data/`",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, err := loader()
			if err != nil {
				return err
			}
			cfg, err := ctx.DataRoot.EnsureProject(projectID, root, githubURL)
			if err != nil {
				return err
			}
			fmt.Printf("Initialized project %q at %s\n", cfg.ProjectID, cfg.RootPath)
			return nil
		},
	}
	cmd.Flags().StringVar(&projectID, "project-id", "", "Project id")
	cmd.Flags().StringVar(&root, "root", ".", "Project root path")
	cmd.Flags().StringVar(&githubURL, "github-url", "", "GitHub blob URL for line links")
	_ = cmd.MarkFlagRequired("project-id")
	return cmd
}
