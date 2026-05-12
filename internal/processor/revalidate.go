package processor

import (
	"context"
	"os"
	"path/filepath"

	"github.com/noeljackson/deepsec/internal/core"
)

// RevalidateOptions configures a revalidate run.
type RevalidateOptions struct {
	ProjectID    string
	ProjectRoot  string
	DataRoot     core.DataRoot
	Backend      AgentBackend
	ProviderName string
	FilterPrefix string
	Force        bool
}

// RevalidateOutcome summarizes the run.
type RevalidateOutcome struct {
	RunID          string
	Revalidated    int
	TruePositives  int
	FalsePositives int
	Fixed          int
	Uncertain      int
}

// Revalidate re-checks every finding without a revalidation field (or
// every finding, if Force is set) against the current source.
func Revalidate(ctx context.Context, opts RevalidateOptions) (*RevalidateOutcome, error) {
	runID := core.GenerateRunID()
	meta := core.NewRunMeta(opts.ProjectID, runID, opts.ProjectRoot, core.RunTypeRevalidate)
	meta.ProcessorConfig = &core.ProcessorConfig{
		AgentType:      opts.ProviderName,
		Model:          opts.Backend.Model(),
		ModelConfig:    map[string]any{},
		InvocationMode: core.InvocationModeScan,
	}
	if err := opts.DataRoot.WriteRunMeta(meta); err != nil {
		return nil, err
	}

	records, err := opts.DataRoot.LoadAllFileRecords(opts.ProjectID)
	if err != nil {
		return nil, err
	}
	outcome := &RevalidateOutcome{RunID: runID}

	for _, rec := range records {
		if opts.FilterPrefix != "" && !hasPrefix(rec.FilePath, opts.FilterPrefix) {
			continue
		}
		var inputs []RevalidateInputFinding
		for i, f := range rec.Findings {
			if !opts.Force && f.Revalidation != nil {
				continue
			}
			inputs = append(inputs, RevalidateInputFinding{
				Index:       i,
				Severity:    f.Severity,
				VulnSlug:    f.VulnSlug,
				Title:       f.Title,
				Description: f.Description,
				LineNumbers: f.LineNumbers,
			})
		}
		if len(inputs) == 0 {
			continue
		}
		body, _ := os.ReadFile(filepath.Join(opts.ProjectRoot, rec.FilePath))
		in := &RevalidateInput{
			ProjectRoot: opts.ProjectRoot,
			FilePath:    rec.FilePath,
			FileContent: string(body),
			Findings:    inputs,
		}
		revs, _, _, err := opts.Backend.Revalidate(ctx, in)
		if err != nil {
			if IsQuotaErr(err) {
				break
			}
			continue
		}
		for _, r := range revs {
			if r.Index < 0 || r.Index >= len(rec.Findings) {
				continue
			}
			f := &rec.Findings[r.Index]
			f.Revalidation = &core.Revalidation{
				Verdict:          r.Verdict,
				Reasoning:        r.Reasoning,
				AdjustedSeverity: r.AdjustedSeverity,
				RevalidatedAt:    core.NowISO(),
				RunID:            runID,
				Model:            opts.Backend.Model(),
			}
			outcome.Revalidated++
			switch r.Verdict {
			case core.VerdictTruePositive, core.VerdictAcceptedRisk:
				outcome.TruePositives++
			case core.VerdictFalsePositive:
				outcome.FalsePositives++
			case core.VerdictFixed:
				outcome.Fixed++
			case core.VerdictUncertain:
				outcome.Uncertain++
			}
		}
		if err := opts.DataRoot.WriteFileRecord(rec); err != nil {
			return nil, err
		}
	}

	meta.Stats.FindingsRevalidated = &outcome.Revalidated
	meta.Stats.TruePositives = &outcome.TruePositives
	meta.Stats.FalsePositives = &outcome.FalsePositives
	meta.Stats.Fixed = &outcome.Fixed
	meta.Stats.Uncertain = &outcome.Uncertain
	if err := opts.DataRoot.WriteRunMeta(meta); err != nil {
		return nil, err
	}
	if _, err := opts.DataRoot.CompleteRun(opts.ProjectID, runID, core.RunPhaseDone); err != nil {
		return nil, err
	}
	return outcome, nil
}
