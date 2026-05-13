package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/noeljackson/deepsec/bench"
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

	root.AddCommand(score, processScore, processCompare, lint, review)
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
