package commands

import (
	"fmt"
	"os"

	"github.com/noeljackson/deepsec/internal/cli"
	"github.com/spf13/cobra"
)

// NewPreflightCmd validates env vars and config for the chosen provider.
func NewPreflightCmd(loader func() (*cli.Context, error)) *cobra.Command {
	var agent string
	cmd := &cobra.Command{
		Use:   "preflight",
		Short: "Validate environment for the chosen backend",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, err := loader()
			if err != nil {
				return err
			}
			agentName := ctx.ResolveAgent(agent)
			if err := cli.Preflight(ctx, agentName); err != nil {
				return err
			}
			p := ctx.Providers.Get(agentName)
			fmt.Printf("preflight ok provider=%s kind=%s model=%s base_url=%s\n",
				p.Name, p.Kind, p.DefaultModel, defaultStr(p.BaseURL, "<sdk default>"))
			if ctx.ConfigPath != "" {
				fmt.Printf("  config: %s\n", ctx.ConfigPath)
			} else {
				fmt.Fprintln(os.Stderr, "  warn: no deepsec.config.toml found")
			}
			fmt.Printf("  data root: %s\n", ctx.DataRoot.Path)
			return nil
		},
	}
	cmd.Flags().StringVar(&agent, "agent", "", "Provider name")
	return cmd
}

func defaultStr(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
