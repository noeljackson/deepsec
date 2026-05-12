package commands

import (
	"fmt"
	"os"
	"strings"

	"github.com/noeljackson/deepsec/internal/cli"
	"github.com/noeljackson/deepsec/internal/scanner"
	"github.com/spf13/cobra"
)

// NewListMatchersCmd prints every bundled matcher.
func NewListMatchersCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list-matchers",
		Short: "Print bundled matcher slugs",
		RunE: func(cmd *cobra.Command, _ []string) error {
			reg, err := scanner.WithBuiltin()
			if err != nil {
				return err
			}
			fmt.Printf("%d matchers\n", reg.Len())
			for _, m := range reg.All() {
				fmt.Printf("  %-40s %-8s %s\n", m.Slug(), strings.ToLower(string(m.NoiseTier())), m.Description())
			}
			return nil
		},
	}
}

// NewListProvidersCmd prints every known provider profile.
func NewListProvidersCmd(loader func() (*cli.Context, error)) *cobra.Command {
	return &cobra.Command{
		Use:   "list-providers",
		Short: "Print known provider profiles",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, err := loader()
			if err != nil {
				return err
			}
			fmt.Printf("%d providers\n", len(ctx.Providers.Names()))
			for _, p := range ctx.Providers.All() {
				keyStatus := "MISSING"
				if os.Getenv(p.APIKeyEnv) != "" {
					keyStatus = "set"
				}
				fmt.Printf("  %-12s kind=%-18s default_model=%-30s %s=%s\n",
					p.Name, p.Kind, p.DefaultModel, p.APIKeyEnv, keyStatus)
			}
			return nil
		},
	}
}
