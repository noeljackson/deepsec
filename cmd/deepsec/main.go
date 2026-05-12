// deepsec — the CLI binary.
package main

import (
	"fmt"
	"os"

	"github.com/noeljackson/deepsec/internal/cli"
	"github.com/noeljackson/deepsec/internal/cli/commands"
	"github.com/spf13/cobra"
)

func main() {
	root := cli.NewRoot(func(root *cobra.Command, loader func() (*cli.Context, error)) {
		root.AddCommand(commands.NewInitCmd(loader))
		root.AddCommand(commands.NewInitProjectCmd(loader))
		root.AddCommand(commands.NewScanCmd(loader))
		root.AddCommand(commands.NewProcessCmd(loader))
		root.AddCommand(commands.NewRevalidateCmd(loader))
		root.AddCommand(commands.NewTriageCmd(loader))
		root.AddCommand(commands.NewEnrichCmd(loader))
		root.AddCommand(commands.NewStatusCmd(loader))
		root.AddCommand(commands.NewReportCmd(loader))
		root.AddCommand(commands.NewExportCmd(loader))
		root.AddCommand(commands.NewMetricsCmd(loader))
		root.AddCommand(commands.NewPrCommentCmd(loader))
		root.AddCommand(commands.NewDataCommitCmd(loader))
		root.AddCommand(commands.NewPreflightCmd(loader))
		root.AddCommand(commands.NewListMatchersCmd())
		root.AddCommand(commands.NewListProvidersCmd(loader))
	})
	if err := root.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
