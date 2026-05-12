package commands

import (
	"context"
	"fmt"

	"github.com/noeljackson/deepsec/internal/cli"
	"github.com/noeljackson/deepsec/internal/processor"
	"github.com/spf13/cobra"
)

// NewRevalidateCmd runs the revalidation stage.
func NewRevalidateCmd(loader func() (*cli.Context, error)) *cobra.Command {
	var projectID, agent, model, filter string
	var force bool
	var temperature, topP float64
	var seed int64
	cmd := &cobra.Command{
		Use:   "revalidate",
		Short: "Re-verify existing findings against the current code",
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
			settings := modelSettingsFromFlags(cmd, temperature, topP, seed)
			backend, err := processor.NewBackend(profile, model, apiKey, settings)
			if err != nil {
				return err
			}
			out, err := processor.Revalidate(context.Background(), processor.RevalidateOptions{
				ProjectID:     projectID,
				ProjectRoot:   proj.Root,
				DataRoot:      ctx.DataRoot,
				Backend:       backend,
				ProviderName:  agentName,
				FilterPrefix:  filter,
				Force:         force,
				ModelSettings: settings,
			})
			if err != nil {
				return err
			}
			fmt.Printf("revalidate run=%s revalidated=%d TP=%d FP=%d fixed=%d uncertain=%d\n",
				out.RunID, out.Revalidated, out.TruePositives, out.FalsePositives, out.Fixed, out.Uncertain)
			return nil
		},
	}
	cmd.Flags().StringVar(&projectID, "project-id", "", "Project id (required)")
	_ = cmd.MarkFlagRequired("project-id")
	cmd.Flags().StringVar(&agent, "agent", "", "Provider name")
	cmd.Flags().StringVar(&model, "model", "", "Override the backend model")
	cmd.Flags().StringVar(&filter, "filter", "", "Path-prefix filter")
	cmd.Flags().BoolVar(&force, "force", false, "Re-revalidate findings that already have a verdict")
	cmd.Flags().Float64Var(&temperature, "temperature", 0, "Pin sampling temperature (default: provider SDK default)")
	cmd.Flags().Float64Var(&topP, "top-p", 0, "Pin nucleus sampling (default: provider SDK default)")
	cmd.Flags().Int64Var(&seed, "seed", 0, "Pin sampler seed; OpenAI-compatible providers only")
	return cmd
}
