package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/noeljackson/deepsec/bench"
	"github.com/noeljackson/deepsec/internal/processor"
	"github.com/noeljackson/deepsec/internal/processor/providers"
	"github.com/spf13/cobra"
)

func main() {
	var tasksDir, outDir string
	var processTasksDir, processOutDir string
	var processRepeat, processBootstrap int
	var processSeed uint64
	var compareThreshold float64
	var compareSeed uint64
	var compareBootstrap int
	var explosion float64
	var reviewSlug, reviewCommit string
	var reviewEdit, reviewEmitFPs, reviewEmitFNs, reviewRescore bool
	var agentSlug, agentHeldOut, agentMockPatch, agentMockNewMatcher, agentProvider, agentModel, agentMode string
	var agentApply bool
	var agentMaxIterations, agentMaxRejections int
	var agentMaxCost, agentCandidateBudget, agentMinPrecision float64
	root := &cobra.Command{Use: "benchsec", Short: "deepsec benchmark harness"}
	score := &cobra.Command{
		Use:   "score [task-id...]",
		Short: "score scanner candidates against benchmark answer keys",
		RunE: func(cmd *cobra.Command, args []string) error {
			result, err := bench.Score(args, bench.ScoreOptions{TasksDir: tasksDir, OutDir: outDir, CandidateExplosion: explosion})
			if err != nil {
				return err
			}
			body, err := json.MarshalIndent(result.Summary, "", "  ")
			if err != nil {
				return err
			}
			fmt.Println(string(body))
			return nil
		},
	}
	score.Flags().StringVar(&tasksDir, "tasks", "bench/tasks", "benchmark task directory")
	score.Flags().StringVar(&outDir, "out", "bench/out", "report output root")
	score.Flags().Float64Var(&explosion, "candidate-explosion", 100, "candidate density threshold per KLOC")

	processScore := &cobra.Command{
		Use:   "process-score [task-id...]",
		Short: "score processor replay fixtures against answer keys",
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := bench.ProcessScoreOptions{
				TasksDir: processTasksDir, OutDir: processOutDir,
				Repeat: processRepeat, Seed: processSeed, BootstrapSamples: processBootstrap,
			}
			if processRepeat > 1 {
				result, err := bench.ProcessScoreRepeated(args, opts)
				if err != nil {
					return err
				}
				body, err := json.MarshalIndent(result, "", "  ")
				if err != nil {
					return err
				}
				fmt.Println(string(body))
				return nil
			}
			result, err := bench.ProcessScore(args, opts)
			if err != nil {
				return err
			}
			body, err := json.MarshalIndent(result.Summary, "", "  ")
			if err != nil {
				return err
			}
			fmt.Println(string(body))
			return nil
		},
	}
	processScore.Flags().StringVar(&processTasksDir, "tasks", "bench/processor-fixtures", "processor fixture directory")
	processScore.Flags().StringVar(&processOutDir, "out", "bench/out-processor", "processor report output root")
	processScore.Flags().IntVar(&processRepeat, "repeat", 1, "number of serial processor scoring repeats")
	processScore.Flags().Uint64Var(&processSeed, "seed", 1, "base seed for repeat and stochastic replay")
	processScore.Flags().IntVar(&processBootstrap, "bootstrap-samples", 1000, "bootstrap resamples for repeated scoring intervals")

	processCompare := &cobra.Command{
		Use:   "process-compare <a-dir> <b-dir>",
		Short: "compare two repeated processor scoring runs",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			report, err := bench.ProcessCompare(args[0], args[1], bench.ProcessCompareOptions{
				Threshold: compareThreshold, Seed: compareSeed, BootstrapSamples: compareBootstrap,
			})
			if err != nil {
				return err
			}
			fmt.Print(bench.ProcessCompareTSV(report))
			return nil
		},
	}
	processCompare.Flags().Float64Var(&compareThreshold, "threshold", 0, "minimum absolute CI exclusion threshold for improved/regressed verdicts")
	processCompare.Flags().Uint64Var(&compareSeed, "seed", 1, "bootstrap seed for comparison intervals")
	processCompare.Flags().IntVar(&compareBootstrap, "bootstrap-samples", 1000, "bootstrap resamples for comparison intervals")

	var matcherDir, format string
	lint := &cobra.Command{
		Use:   "lint-matchers",
		Short: "lint bundled matcher TOML files",
		RunE: func(cmd *cobra.Command, args []string) error {
			findings, err := bench.LintMatchers(matcherDir)
			if err != nil {
				return err
			}
			switch format {
			case "json":
				body, err := json.MarshalIndent(findings, "", "  ")
				if err != nil {
					return err
				}
				fmt.Println(string(body))
			case "tsv":
				fmt.Println("severity\tfile\tline\tslug\tcheck\tmessage")
				for _, f := range findings {
					fmt.Println(f.TSV())
				}
			default:
				return fmt.Errorf("unsupported format %q", format)
			}
			if bench.HasLintErrors(findings) {
				return fmt.Errorf("matcher lint found error-level findings")
			}
			return nil
		},
	}
	lint.Flags().StringVar(&matcherDir, "matchers", "internal/scanner/matchers", "matcher TOML directory")
	lint.Flags().StringVar(&format, "format", "tsv", "output format: tsv or json")

	review := &cobra.Command{
		Use:   "review --slug <slug>",
		Short: "review per-slug scanner false positives and false negatives",
		RunE: func(cmd *cobra.Command, args []string) error {
			return bench.RunReview(bench.ReviewOptions{
				Slug:          reviewSlug,
				TasksDir:      tasksDir,
				OutDir:        outDir,
				Edit:          reviewEdit,
				CommitMessage: reviewCommit,
				EmitFPs:       reviewEmitFPs,
				EmitFNs:       reviewEmitFNs,
				Rescore:       reviewRescore,
			})
		},
	}
	review.Flags().StringVar(&reviewSlug, "slug", "", "matcher slug to review")
	review.Flags().BoolVar(&reviewEdit, "edit", false, "edit the bundled matcher TOML and rescore")
	review.Flags().StringVar(&reviewCommit, "commit", "", "commit an accepted matcher edit with this message")
	review.Flags().BoolVar(&reviewEmitFPs, "emit-fps", false, "emit false positives as JSON")
	review.Flags().BoolVar(&reviewEmitFNs, "emit-fns", false, "emit false negatives as JSON")
	review.Flags().BoolVar(&reviewRescore, "rescore", false, "rescore the slug without editing")
	review.Flags().StringVar(&tasksDir, "tasks", "bench/tasks", "benchmark task directory")
	review.Flags().StringVar(&outDir, "out", "bench/out", "report output root")
	if err := review.MarkFlagRequired("slug"); err != nil {
		panic(err)
	}

	agent := &cobra.Command{
		Use:   "agent",
		Short: "run the bounded matcher-patch agent (precision or recall mode)",
		RunE: func(cmd *cobra.Command, args []string) error {
			mode := strings.TrimSpace(agentMode)
			if mode == "" {
				mode = "precision"
			}
			switch mode {
			case "precision":
				opts := bench.AgentOptions{
					Slug:                  agentSlug,
					TasksDir:              tasksDir,
					OutDir:                outDir,
					Apply:                 agentApply,
					MaxIterations:         agentMaxIterations,
					MaxRejections:         agentMaxRejections,
					MaxCostUSD:            agentMaxCost,
					CandidateGrowthBudget: agentCandidateBudget,
					HeldOut:               splitCSV(agentHeldOut),
					RunTests:              agentApply,
					RequireClean:          agentApply,
					Out:                   os.Stdout,
				}
				if agentMockPatch != "" {
					p, err := processor.ParsePatch(agentMockPatch)
					if err != nil {
						return err
					}
					opts.MockPatch = &p
				} else {
					backend, err := newAgentBackend(agentProvider, agentModel)
					if err != nil {
						return err
					}
					opts.Backend = backend
				}
				return bench.RunAgent(context.Background(), opts)
			case "recall":
				opts := bench.RecallAgentOptions{
					Slug:                  agentSlug,
					TasksDir:              tasksDir,
					OutDir:                outDir,
					Apply:                 agentApply,
					MaxIterations:         agentMaxIterations,
					MaxRejections:         agentMaxRejections,
					MaxCostUSD:            agentMaxCost,
					CandidateGrowthBudget: agentCandidateBudget,
					MinPrecision:          agentMinPrecision,
					HeldOut:               splitCSV(agentHeldOut),
					RunTests:              agentApply,
					RequireClean:          agentApply,
					Out:                   os.Stdout,
				}
				if agentMockNewMatcher != "" {
					p, err := processor.ParseNewMatcher(agentMockNewMatcher)
					if err != nil {
						return err
					}
					opts.MockProposal = &p
				} else {
					backend, err := newAgentBackend(agentProvider, agentModel)
					if err != nil {
						return err
					}
					opts.Backend = backend
				}
				return bench.RunRecallAgent(context.Background(), opts)
			default:
				return fmt.Errorf("unsupported --mode %q (want precision|recall)", mode)
			}
		},
	}
	agent.Flags().StringVar(&agentSlug, "slug", "", "matcher slug to improve; defaults to worst precision slug with >1 FP")
	agent.Flags().BoolVar(&agentApply, "apply", false, "apply accepted patches and commit them")
	agent.Flags().IntVar(&agentMaxIterations, "max-iterations", 1, "maximum accepted patches per invocation")
	agent.Flags().IntVar(&agentMaxRejections, "max-rejections", 3, "halt after this many consecutive rejected proposals")
	agent.Flags().Float64Var(&agentMaxCost, "max-cost-usd", 0, "maximum proposer cost budget; 0 means provider default/subscription")
	agent.Flags().Float64Var(&agentCandidateBudget, "candidate-growth-budget", 0.05, "relative candidate-count growth budget")
	agent.Flags().StringVar(&agentHeldOut, "held-out", "", "comma-separated task IDs excluded from gate/context and scored separately")
	agent.Flags().StringVar(&agentProvider, "provider", "zai-coding", "provider profile for the proposer")
	agent.Flags().StringVar(&agentModel, "model", "", "override proposer model")
	agent.Flags().StringVar(&agentMockPatch, "mock-patch", "", "strict JSON patch used instead of calling an LLM (precision mode)")
	agent.Flags().StringVar(&agentMockNewMatcher, "mock-proposal", "", "strict JSON new-matcher proposal used instead of calling an LLM (recall mode)")
	agent.Flags().StringVar(&agentMode, "mode", "precision", "agent mode: precision (narrow existing matchers) or recall (propose new matchers)")
	agent.Flags().Float64Var(&agentMinPrecision, "min-precision", 0.25, "minimum precision required of a recall-mode proposal's new slug")
	agent.Flags().StringVar(&tasksDir, "tasks", "bench/tasks", "benchmark task directory")
	agent.Flags().StringVar(&outDir, "out", "bench/out-agent", "agent report output root")

	var staleTasksDir string
	stale := &cobra.Command{
		Use:   "stale",
		Short: "list bench tasks whose answer-key review_due has passed",
		RunE: func(cmd *cobra.Command, args []string) error {
			rows, err := bench.StaleTasks(staleTasksDir, time.Now().UTC())
			if err != nil {
				return err
			}
			if len(rows) == 0 {
				fmt.Println("no stale tasks")
				return nil
			}
			fmt.Printf("%-40s %-20s %-12s %s\n", "task", "reviewer", "due", "overdue")
			for _, r := range rows {
				days := int(r.OverdueBy.Hours() / 24)
				fmt.Printf("%-40s %-20s %-12s %dd\n", r.TaskID, r.Reviewer, r.ReviewDue, days)
			}
			return fmt.Errorf("%d task(s) past review_due", len(rows))
		},
	}
	stale.Flags().StringVar(&staleTasksDir, "tasks", "bench/tasks", "benchmark task directory")

	root.AddCommand(score, processScore, processCompare, lint, review, agent, stale)
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newAgentBackend(providerName, model string) (processor.AgentBackend, error) {
	reg, err := providers.LoadBuiltin()
	if err != nil {
		return nil, err
	}
	profile := reg.Get(providerName)
	if profile == nil {
		return nil, fmt.Errorf("unknown provider %q", providerName)
	}
	key, err := reg.LookupKey(providerName)
	if err != nil {
		return nil, err
	}
	return processor.NewBackend(profile, model, key, processor.ModelSettings{})
}

func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
