package processor

import (
	"context"

	"github.com/noeljackson/deepsec/internal/core"
)

// TriageOptions configures a triage run.
type TriageOptions struct {
	ProjectID    string
	ProjectRoot  string
	DataRoot     core.DataRoot
	Backend      AgentBackend
	ProviderName string
	FilterPrefix string
	Force        bool
}

// TriageOutcome summarizes a triage run.
type TriageOutcome struct {
	RunID   string
	Triaged int
}

// Triage assigns priority/exploitability/impact to findings that don't
// already have a triage field (or every finding, if Force is set).
func Triage(ctx context.Context, opts TriageOptions) (*TriageOutcome, error) {
	runID := core.GenerateRunID()
	meta := core.NewRunMeta(opts.ProjectID, runID, opts.ProjectRoot, core.RunTypeProcess)
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
	out := &TriageOutcome{RunID: runID}
	for _, rec := range records {
		if opts.FilterPrefix != "" && !hasPrefix(rec.FilePath, opts.FilterPrefix) {
			continue
		}
		changed := false
		for i := range rec.Findings {
			if !opts.Force && rec.Findings[i].Triage != nil {
				continue
			}
			f := rec.Findings[i]
			in := &TriageInput{
				FilePath: rec.FilePath,
				Finding: RevalidateInputFinding{
					Index:       i,
					Severity:    f.Severity,
					VulnSlug:    f.VulnSlug,
					Title:       f.Title,
					Description: f.Description,
					LineNumbers: f.LineNumbers,
				},
			}
			t, _, _, err := opts.Backend.Triage(ctx, in)
			if err != nil {
				if IsQuotaErr(err) {
					goto done
				}
				continue
			}
			rec.Findings[i].Triage = &core.Triage{
				Priority:       t.Priority,
				Exploitability: t.Exploitability,
				Impact:         t.Impact,
				Reasoning:      t.Reasoning,
				TriagedAt:      core.NowISO(),
				Model:          opts.Backend.Model(),
			}
			out.Triaged++
			changed = true
		}
		if changed {
			if err := opts.DataRoot.WriteFileRecord(rec); err != nil {
				return nil, err
			}
		}
	}
done:
	if err := opts.DataRoot.WriteRunMeta(meta); err != nil {
		return nil, err
	}
	if _, err := opts.DataRoot.CompleteRun(opts.ProjectID, runID, core.RunPhaseDone); err != nil {
		return nil, err
	}
	return out, nil
}
