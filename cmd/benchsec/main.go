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
	var explosion float64
	root := &cobra.Command{Use: "benchsec", Short: "scanner-only benchmark harness"}
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

	root.AddCommand(score, lint)
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
