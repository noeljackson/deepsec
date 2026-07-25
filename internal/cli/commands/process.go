package commands

import (
	"context"
	"fmt"
	"strings"

	"github.com/noeljackson/deepsec/internal/cli"
	"github.com/noeljackson/deepsec/internal/processor"
	"github.com/noeljackson/deepsec/internal/scanner"
	"github.com/spf13/cobra"
)

// NewProcessCmd runs the AI investigation pipeline.
func NewProcessCmd(loader func() (*cli.Context, error)) *cobra.Command {
	var (
		projectID, agent, agentsCSV, model, filter, onlySlugs, skipSlugs, filesFrom, diff, record, failOn string
		files                                                                                             []string
		batchSize, concurrency, limit, reinvestigate, maxTurns                                            int
		maxCost, temperature, topP                                                                        float64
		seed                                                                                              int64
		toolsEnabled, skepticEnabled                                                                      bool
	)
	cmd := &cobra.Command{
		Use:   "process",
		Short: "Investigate pending candidates with an AI backend",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if maxCost <= 0 {
				return fmt.Errorf("--max-cost-usd must be greater than zero")
			}
			ctx, err := loader()
			if err != nil {
				return err
			}
			proj, err := ctx.Project(projectID)
			if err != nil {
				return err
			}
			settings := modelSettingsFromFlags(cmd, temperature, topP, seed)
			agentNames := splitCSV(agentsCSV)
			if len(agentNames) == 0 {
				agentNames = []string{ctx.ResolveAgent(agent)}
			}
			var namedBackends []processor.NamedBackend
			for _, name := range agentNames {
				if err := cli.Preflight(ctx, name); err != nil {
					return err
				}
				profile := ctx.Providers.Get(name)
				if profile == nil {
					return fmt.Errorf("unknown provider %q", name)
				}
				apiKey, err := ctx.Providers.LookupKey(name)
				if err != nil {
					return err
				}
				b, err := processor.NewBackend(profile, model, apiKey, settings)
				if err != nil {
					return err
				}
				namedBackends = append(namedBackends, processor.NamedBackend{Name: name, Backend: b})
			}
			// Recording wraps only the first (or only) backend — ensemble
			// runs would multiply replay fixtures across providers and
			// the captured shape would be ambiguous.
			if record != "" {
				rec, err := processor.NewRecordingBackend(namedBackends[0].Backend, record)
				if err != nil {
					return err
				}
				defer func() { _ = rec.Close() }()
				namedBackends[0].Backend = rec
			}
			agentName := namedBackends[0].Name
			backend := namedBackends[0].Backend

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

			procOpts := processor.ProcessOptions{
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
				ToolsEnabled:      toolsEnabled,
				MaxTurns:          maxTurns,
				SkepticEnabled:    skepticEnabled,
				Detected:          tech,
				ModelSettings:     settings,
			}
			if len(namedBackends) > 1 {
				ens, err := processor.EnsembleProcess(context.Background(), procOpts, namedBackends)
				if err != nil {
					return err
				}
				fmt.Printf("ensemble runs=%d agents=%s\n", len(ens.RunIDs), strings.Join(agentNames, ","))
				fmt.Printf("  unique findings: %d  (consensus=%d  solo=%d)\n",
					ens.UniqueFindings, ens.ConsensusCount, ens.SoloCount)
				for i, oc := range ens.Outcomes {
					fmt.Printf("  [%s] run=%s findings=%d cost=$%.4f\n",
						agentNames[i], oc.RunID, oc.FindingCount, oc.TotalCostUSD)
				}
				if failOn != "" {
					// Run-id scoping doesn't fit ensemble; use empty
					// runID to scope across all findings in the project.
					return enforceFailOn(ctx, projectID, "", failOn)
				}
				return nil
			}
			out, err := processor.Process(context.Background(), procOpts)
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
			if failOn != "" {
				return enforceFailOn(ctx, projectID, out.RunID, failOn)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&projectID, "project-id", "", "Project id (required)")
	_ = cmd.MarkFlagRequired("project-id")
	cmd.Flags().StringVar(&agent, "agent", "", "Provider name (defaults to config.default_agent or 'anthropic')")
	cmd.Flags().StringVar(&agentsCSV, "agents", "", "Multi-model ensemble: csv of provider names; runs each agent over the same candidates and tags findings with AgreeingAgents (~N× cost)")
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
	cmd.Flags().Float64Var(&maxCost, "max-cost-usd", 5.0, "Abort the run when cumulative cost exceeds this USD amount (must be finite and greater than zero)")
	cmd.Flags().BoolVar(&toolsEnabled, "tools", false, "Enable multi-turn read-only investigation tools")
	cmd.Flags().IntVar(&maxTurns, "max-turns", 8, "Max model turns per investigation when --tools is enabled")
	cmd.Flags().BoolVar(&skepticEnabled, "skeptic", false, "Second-pass adversarial review: try to disprove each finding before persisting it")
	cmd.Flags().StringVar(&failOn, "fail-on", "", "Exit non-zero when this run produces a finding at or above this severity (CRITICAL|HIGH|MEDIUM|LOW)")
	cmd.Flags().Float64Var(&temperature, "temperature", 0, "Pin sampling temperature (default: provider SDK default)")
	cmd.Flags().Float64Var(&topP, "top-p", 0, "Pin nucleus sampling (default: provider SDK default)")
	cmd.Flags().Int64Var(&seed, "seed", 0, "Pin sampler seed; OpenAI-compatible providers only")
	cmd.Flags().StringVar(&record, "record", "", "Tee every backend response into this JSONL path (use to capture a fixture under bench/processor-fixtures/)")
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
