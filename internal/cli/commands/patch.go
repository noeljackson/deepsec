package commands

import (
	"context"
	"fmt"
	"time"

	"github.com/noeljackson/deepsec/internal/cli"
	"github.com/noeljackson/deepsec/internal/processor"
	"github.com/spf13/cobra"
)

// NewPatchCmd proposes, validates, and optionally commits source fixes for findings.
func NewPatchCmd(loader func() (*cli.Context, error)) *cobra.Command {
	var (
		projectID, findingID, sinceRun, severity, slug, agent, model, validate string
		maxPerRun                                                              int
		maxCost, temperature, topP                                             float64
		seed                                                                   int64
		apply, push, withTools                                                 bool
		validationTimeout                                                      time.Duration
	)
	cmd := &cobra.Command{
		Use:   "patch",
		Short: "Generate and validate source patches for findings",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if push && !apply {
				return fmt.Errorf("--push requires --apply")
			}
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
			records, err := ctx.DataRoot.LoadAllFileRecords(projectID)
			if err != nil {
				return err
			}
			findings, err := processor.BuildPatchFindings(projectID, proj.Root, records, sinceRun, splitCSV(severity), splitCSV(slug))
			if err != nil {
				return err
			}
			if findingID != "" {
				findings = filterPatchFindingID(findings, findingID)
			}
			if len(findings) == 0 {
				return fmt.Errorf("no matching findings")
			}
			if maxPerRun <= 0 {
				maxPerRun = 1
			}
			if len(findings) > maxPerRun {
				findings = findings[:maxPerRun]
			}
			runOpts := processor.PatchRunOptions{
				ProjectID: projectID, ProjectRoot: proj.Root, GithubURL: proj.Decl.GithubURL,
				DataRoot: ctx.DataRoot, Backend: backend, ProviderName: agentName,
				ModelSettings: settings, ValidateCommand: validate, ValidationTimeout: validationTimeout,
				Apply: apply, Push: push, WithTools: withTools, MaxCostUSD: maxCost,
			}
			for _, f := range findings {
				if _, err := processor.RunPatch(context.Background(), runOpts, f); err != nil {
					return err
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&projectID, "project-id", "", "Project id (required)")
	_ = cmd.MarkFlagRequired("project-id")
	cmd.Flags().StringVar(&findingID, "finding-id", "", "Patch one finding id")
	cmd.Flags().StringVar(&sinceRun, "since-run", "", "Patch findings produced by this run id")
	cmd.Flags().StringVar(&severity, "severity", "", "Only patch these severities (csv)")
	cmd.Flags().StringVar(&slug, "slug", "", "Only patch these vulnerability slugs (csv)")
	cmd.Flags().StringVar(&agent, "agent", "", "Provider name (defaults to config.default_agent or 'anthropic')")
	cmd.Flags().StringVar(&model, "model", "", "Override the backend model")
	cmd.Flags().StringVar(&validate, "validate", "", "Validation command run inside the sandbox clone")
	cmd.Flags().BoolVar(&apply, "apply", false, "Commit the validated patch on a deepsec-patch branch")
	cmd.Flags().BoolVar(&push, "push", false, "Push the branch and open a PR with gh; requires --apply")
	cmd.Flags().IntVar(&maxPerRun, "max-per-run", 1, "Maximum findings patched per invocation")
	cmd.Flags().Float64Var(&maxCost, "max-cost-usd", 0, "Abort the patcher when cumulative provider cost reaches this USD amount")
	cmd.Flags().Float64Var(&temperature, "temperature", 0, "Pin sampling temperature (default: provider SDK default)")
	cmd.Flags().Float64Var(&topP, "top-p", 0, "Pin nucleus sampling (default: provider SDK default)")
	cmd.Flags().Int64Var(&seed, "seed", 0, "Pin sampler seed; OpenAI-compatible providers only")
	cmd.Flags().BoolVar(&withTools, "with-tools", false, "Allow read-only codebase tools before proposing a diff")
	cmd.Flags().DurationVar(&validationTimeout, "validation-timeout", 5*time.Minute, "Validation command timeout")
	return cmd
}

func filterPatchFindingID(findings []processor.PatchFinding, id string) []processor.PatchFinding {
	out := findings[:0]
	for _, f := range findings {
		if f.ID == id {
			out = append(out, f)
		}
	}
	return out
}
