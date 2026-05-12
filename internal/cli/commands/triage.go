package commands

import (
	"context"
	"fmt"

	"github.com/noeljackson/deepsec/internal/cli"
	"github.com/noeljackson/deepsec/internal/processor"
	"github.com/spf13/cobra"
)

// NewTriageCmd runs the triage stage.
func NewTriageCmd(loader func() (*cli.Context, error)) *cobra.Command {
	var projectID, agent, model, filter string
	var force bool
	cmd := &cobra.Command{
		Use:   "triage",
		Short: "Assign priority/exploitability/impact to findings",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, err := loader()
			if err != nil {
				return err
			}
			proj, err := ctx.Project(projectID)
			if err != nil {
				return err
			}
			agentName := ctx.ResolveAgent(agent)
			if err := cli.Preflight(ctx, agentName); err != nil {
				return err
			}
			profile := ctx.Providers.Get(agentName)
			apiKey, err := ctx.Providers.LookupKey(agentName)
			if err != nil {
				return err
			}
			backend, err := processor.NewBackend(profile, model, apiKey)
			if err != nil {
				return err
			}
			out, err := processor.Triage(context.Background(), processor.TriageOptions{
				ProjectID:    projectID,
				ProjectRoot:  proj.Root,
				DataRoot:     ctx.DataRoot,
				Backend:      backend,
				ProviderName: agentName,
				FilterPrefix: filter,
				Force:        force,
			})
			if err != nil {
				return err
			}
			fmt.Printf("triage run=%s triaged=%d\n", out.RunID, out.Triaged)
			return nil
		},
	}
	cmd.Flags().StringVar(&projectID, "project-id", "", "Project id (required)")
	_ = cmd.MarkFlagRequired("project-id")
	cmd.Flags().StringVar(&agent, "agent", "", "Provider name")
	cmd.Flags().StringVar(&model, "model", "", "Override the backend model")
	cmd.Flags().StringVar(&filter, "filter", "", "Path-prefix filter")
	cmd.Flags().BoolVar(&force, "force", false, "Re-triage findings that already have a triage entry")
	return cmd
}
