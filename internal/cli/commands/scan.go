package commands

import (
	"fmt"
	"strings"

	"github.com/noeljackson/deepsec/internal/cli"
	"github.com/noeljackson/deepsec/internal/scanner"
	"github.com/spf13/cobra"
)

// NewScanCmd runs the regex scanner.
func NewScanCmd(loader func() (*cli.Context, error)) *cobra.Command {
	var projectID, rootOverride, matchers, skipMatchers, filesFrom, diff string
	var files []string
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Run the regex scanner over a project",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, err := loader()
			if err != nil {
				return err
			}
			proj, err := ctx.Project(projectID)
			if err != nil {
				return err
			}
			root := proj.Root
			if rootOverride != "" {
				root = rootOverride
			}
			only := splitCSV(matchers)
			exclude := splitCSV(skipMatchers)
			if ctx.Config != nil {
				if len(only) == 0 {
					only = ctx.Config.Matchers.Only
				}
				if len(exclude) == 0 {
					exclude = ctx.Config.Matchers.Exclude
				}
			}

			opts := scanner.Options{
				ProjectID:      projectID,
				Root:           root,
				DataRoot:       ctx.DataRoot,
				MatcherOnly:    only,
				MatcherExclude: exclude,
				GithubURL:      proj.Decl.GithubURL,
			}

			resolved, err := cli.ResolveFiles(cli.FileSourceArgs{
				Files:     files,
				FilesFrom: filesFrom,
				Diff:      diff,
			}, root)
			if err != nil {
				return err
			}
			if resolved != nil {
				out, err := scanner.ScanFiles(opts, resolved.Files, resolved.Source)
				if err != nil {
					return err
				}
				fmt.Printf("scan run=%s mode=files source=%s files=%d candidates=%d\n",
					out.RunID, resolved.Source, out.FilesScanned, out.CandidateCount)
				fmt.Printf("  tech tags: %s\n", strings.Join(out.Detected.Tags, ", "))
				fmt.Printf("  matchers active=%d skipped=%d\n", len(out.ActiveMatchers), len(out.SkippedMatchers))
				return nil
			}

			out, err := scanner.Scan(opts)
			if err != nil {
				return err
			}
			fmt.Printf("scan run=%s files=%d candidates=%d\n",
				out.RunID, out.FilesScanned, out.CandidateCount)
			fmt.Printf("  tech tags: %s\n", strings.Join(out.Detected.Tags, ", "))
			fmt.Printf("  matchers active=%d skipped=%d\n", len(out.ActiveMatchers), len(out.SkippedMatchers))
			if len(out.LanguageStats) > 0 {
				fmt.Println("  by language:")
				for _, s := range out.LanguageStats {
					fmt.Printf("    %12s: %5d files  hits in %4d\n",
						s.Language, s.FilesScanned, s.FilesWithMatch)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&projectID, "project-id", "", "Project id (required)")
	_ = cmd.MarkFlagRequired("project-id")
	cmd.Flags().StringVar(&rootOverride, "root", "", "Override project root")
	cmd.Flags().StringVar(&matchers, "matchers", "", "Only run these matcher slugs (csv)")
	cmd.Flags().StringVar(&skipMatchers, "skip-matchers", "", "Skip these matcher slugs (csv)")
	cmd.Flags().StringSliceVar(&files, "files", nil, "Explicit file list (csv or repeated)")
	cmd.Flags().StringVar(&filesFrom, "files-from", "", `Read file paths from this file ("-" reads stdin)`)
	cmd.Flags().StringVar(&diff, "diff", "", "Scan only files changed vs this git ref")
	return cmd
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
