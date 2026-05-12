package commands

import (
	"context"
	"fmt"

	"github.com/noeljackson/deepsec/internal/cli"
	"github.com/noeljackson/deepsec/internal/processor"
	"github.com/noeljackson/deepsec/internal/scanner"
	"github.com/spf13/cobra"
)

// NewProcessCmd runs the AI investigation pipeline.
func NewProcessCmd(loader func() (*cli.Context, error)) *cobra.Command {
	var (
		projectID, agent, model, filter, onlySlugs, skipSlugs, filesFrom, diff string
		files                                                                  []string
		batchSize, concurrency, limit, reinvestigate                           int
		maxCost, temperature, topP                                             float64
		seed                                                                   int64
	)
	cmd := &cobra.Command{
		Use:   "process",
		Short: "Investigate pending candidates with an AI backend",
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
			if profile == nil {
				return fmt.Errorf("unknown provider %q", agentName)
			}
			apiKey, err := ctx.Providers.LookupKey(agentName)
			if err != nil {
				return err
			}
			settings := modelSettingsFromFlags(cmd, temperature, topP, seed)
			backend, err := processor.NewBackend(profile, model, apiKey, settings)
			if err != nil {
				return err
			}

			resolved, err := cli.ResolveFiles(cli.FileSourceArgs{
				Files:     files,
				FilesFrom: filesFrom,
				Diff:      diff,
			}, proj.Root)
			if err != nil {
				return err
			}

			var directFiles []string
			var directSource string
			if resolved != nil {
				// Direct mode: pre-scan the listed files to populate
				// FileRecord candidates, then process exactly those paths.
				scanOpts := scanner.Options{
					ProjectID:      projectID,
					Root:           proj.Root,
					DataRoot:       ctx.DataRoot,
					MatcherOnly:    nil,
					MatcherExclude: nil,
					GithubURL:      proj.Decl.GithubURL,
				}
				if ctx.Config != nil {
					scanOpts.MatcherOnly = ctx.Config.Matchers.Only
					scanOpts.MatcherExclude = ctx.Config.Matchers.Exclude
				}
				if _, err := scanner.ScanFiles(scanOpts, resolved.Files, resolved.Source); err != nil {
					return err
				}
				directFiles = resolved.Files
				directSource = resolved.Source
			}

			tech, _ := scanner.ReadTechJSON(ctx.DataRoot, projectID)

			out, err := processor.Process(context.Background(), processor.ProcessOptions{
				ProjectID:         projectID,
				ProjectRoot:       proj.Root,
				DataRoot:          ctx.DataRoot,
				Backend:           backend,
				ProviderName:      agentName,
				BatchSize:         batchSize,
				Concurrency:       concurrency,
				Limit:             limit,
				FilterPrefix:      filter,
				OnlySlugs:         splitCSV(onlySlugs),
				SkipSlugs:         splitCSV(skipSlugs),
				ProjectInfo:       proj.Decl.InfoMarkdown,
				PromptAppend:      proj.Decl.PromptAppend,
				DirectFiles:       directFiles,
				DirectSource:      directSource,
				ReinvestigateMark: reinvestigate,
				MaxCostUSD:        maxCost,
				Detected:          tech,
				ModelSettings:     settings,
			})
			if err != nil {
				return err
			}
			fmt.Printf("process run=%s batches=%d files_analyzed=%d findings=%d errors=%d cost=$%.4f",
				out.RunID, out.BatchesRun, out.AnalysisCount, out.FindingCount, out.ErrorBatchCount, out.TotalCostUSD)
			if out.QuotaExhausted {
				fmt.Print(" (quota exhausted)")
			}
			if out.BudgetExhausted {
				fmt.Print(" (budget cap reached)")
			}
			fmt.Println()
			return nil
		},
	}
	cmd.Flags().StringVar(&projectID, "project-id", "", "Project id (required)")
	_ = cmd.MarkFlagRequired("project-id")
	cmd.Flags().StringVar(&agent, "agent", "", "Provider name (defaults to config.default_agent or 'anthropic')")
	cmd.Flags().StringVar(&model, "model", "", "Override the backend model")
	cmd.Flags().IntVar(&batchSize, "batch-size", 5, "Files per batch sent to the model")
	cmd.Flags().IntVar(&concurrency, "concurrency", 4, "Max concurrent in-flight batches")
	cmd.Flags().IntVar(&limit, "limit", 0, "Cap total files processed (0 = no cap)")
	cmd.Flags().StringVar(&filter, "filter", "", "Only process files whose path starts with this prefix")
	cmd.Flags().StringVar(&onlySlugs, "only-slugs", "", "Only process candidates with these slugs (csv)")
	cmd.Flags().StringVar(&skipSlugs, "skip-slugs", "", "Skip candidates with these slugs (csv)")
	cmd.Flags().StringSliceVar(&files, "files", nil, "Direct mode: explicit file list")
	cmd.Flags().StringVar(&filesFrom, "files-from", "", "Direct mode: read file paths from this file (- = stdin)")
	cmd.Flags().StringVar(&diff, "diff", "", "Direct mode: process only files changed vs this git ref")
	cmd.Flags().IntVar(&reinvestigate, "reinvestigate", 0, "Wave marker (skip files already analyzed at this marker)")
	cmd.Flags().Float64Var(&maxCost, "max-cost-usd", 0, "Abort the run when cumulative cost exceeds this USD amount")
	cmd.Flags().Float64Var(&temperature, "temperature", 0, "Pin sampling temperature (default: provider SDK default)")
	cmd.Flags().Float64Var(&topP, "top-p", 0, "Pin nucleus sampling (default: provider SDK default)")
	cmd.Flags().Int64Var(&seed, "seed", 0, "Pin sampler seed; OpenAI-compatible providers only")
	return cmd
}

// modelSettingsFromFlags converts the temperature/top-p/seed flags into
// a ModelSettings struct. Each field is left nil unless the user
// explicitly passed the flag — preserves SDK-default behavior when no
// pin is requested.
func modelSettingsFromFlags(cmd *cobra.Command, temperature, topP float64, seed int64) processor.ModelSettings {
	s := processor.ModelSettings{}
	if cmd.Flags().Changed("temperature") {
		s.Temperature = &temperature
	}
	if cmd.Flags().Changed("top-p") {
		s.TopP = &topP
	}
	if cmd.Flags().Changed("seed") {
		s.Seed = &seed
	}
	return s
}
