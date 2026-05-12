package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/noeljackson/deepsec/internal/cli"
	"github.com/spf13/cobra"
)

const initTemplate = "# deepsec configuration. See docs/configuration.md.\n" +
	"\n" +
	"# Where deepsec writes file-record JSON and run metadata. Default: \"data\".\n" +
	"# data_dir = \"data\"\n" +
	"\n" +
	"# Default AI provider for `deepsec process`. One of: anthropic | openai |\n" +
	"# glm | kimi | deepseek | openrouter | <any custom provider you define\n" +
	"# below>.\n" +
	"default_agent = \"anthropic\"" + `

[matchers]
# Only run these matcher slugs. Empty = run everything bundled.
# only = []
# Never run these matcher slugs.
# exclude = []
# Load additional matcher TOML files (paths relative to this config).
# extra_paths = ["./my-matchers/internal.toml"]

[[projects]]
id = "PROJECT_ID"
root = "PROJECT_ROOT"
# github_url = "https://github.com/example/repo/blob/main"
# info_markdown = """
# Project-specific context surfaced to the AI agent.
# """
# prompt_append = "Pay extra attention to /api/admin/*."
priority_paths = []

# Custom providers (uncomment to enable). The built-in lineup includes:
# anthropic, openai. Opt-in via uncomment: glm, kimi, deepseek, openrouter.
#
# [providers.my-azure]
# kind = "openai-compatible"
# base_url = "https://my-resource.openai.azure.com/openai/deployments/gpt-4"
# api_key_env = "AZURE_OPENAI_KEY"
# default_model = "gpt-4"
# headers = { "api-version" = "2024-08-01-preview" }
# caps = { tool_use = true, prompt_cache = "auto", structured_output = "json_schema" }
`

// NewInitCmd writes a starter deepsec.config.toml.
func NewInitCmd(loader func() (*cli.Context, error)) *cobra.Command {
	var output, root, projectID string
	var force bool
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Write a starter deepsec.config.toml",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cwd, err := os.Getwd()
			if err != nil {
				return err
			}
			path := output
			if path == "" {
				path = filepath.Join(cwd, "deepsec.config.toml")
			}
			if _, err := os.Stat(path); err == nil && !force {
				return fmt.Errorf("%s already exists; use --force to overwrite", path)
			}
			body := strings.NewReplacer(
				"PROJECT_ID", projectID,
				"PROJECT_ROOT", root,
			).Replace(initTemplate)
			if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
				return err
			}
			fmt.Printf("Wrote %s\n", path)
			return nil
		},
	}
	cmd.Flags().StringVar(&output, "output", "", "Path to write deepsec.config.toml")
	cmd.Flags().StringVar(&root, "root", ".", "Project root for the initial project")
	cmd.Flags().StringVar(&projectID, "project-id", "default", "ID for the initial project")
	cmd.Flags().BoolVar(&force, "force", false, "Overwrite an existing config")
	return cmd
}
