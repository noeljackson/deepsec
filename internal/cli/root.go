package cli

import (
	"github.com/spf13/cobra"
)

// NewRoot builds the cobra command tree. Sub-commands are wired in via
// the loader closure so they share one parsed Context.
func NewRoot(addCommands func(*cobra.Command, func() (*Context, error))) *cobra.Command {
	var configPath, dataDir string
	cached := struct {
		ctx *Context
		err error
	}{}

	root := &cobra.Command{
		Use:           "deepsec",
		Short:         "Multi-pass security scanner with AI-assisted investigation",
		SilenceUsage:  true,
		SilenceErrors: false,
	}
	root.PersistentFlags().StringVar(&configPath, "config", "", "Path to deepsec.config.toml")
	root.PersistentFlags().StringVar(&dataDir, "data-dir", "", "Override on-disk data root")

	loader := func() (*Context, error) {
		if cached.ctx != nil || cached.err != nil {
			return cached.ctx, cached.err
		}
		cached.ctx, cached.err = LoadContext(configPath, dataDir)
		return cached.ctx, cached.err
	}
	addCommands(root, loader)
	return root
}
