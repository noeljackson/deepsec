package processor

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/noeljackson/deepsec/internal/core"
	"github.com/noeljackson/deepsec/internal/scanner"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
)

// ProcessOptions bundles everything `Process` needs.
type ProcessOptions struct {
	ProjectID         string
	ProjectRoot       string
	DataRoot          core.DataRoot
	Backend           AgentBackend
	ProviderName      string
	BatchSize         int
	Concurrency       int
	Limit             int // 0 = no limit
	FilterPrefix      string
	OnlySlugs         []string
	SkipSlugs         []string
	ProjectInfo       string
	PromptAppend      string
	DirectFiles       []string // direct mode: bypass status filter
	DirectSource      string
	ReinvestigateMark int // 0 = no marker
	MaxCostUSD        float64
	ToolsEnabled      bool
	MaxTurns          int
	SkepticEnabled    bool
	Detected          *scanner.DetectedTech
	// ModelSettings captures the pinned inference knobs (temperature,
	// top-p, seed) for this run. Persisted in
	// ProcessorConfig.ModelConfig and replayed on each AnalysisEntry so
	// processor evaluations are reproducible.
	ModelSettings ModelSettings
}

// ProcessOutcome summarizes one Process run.
type ProcessOutcome struct {
	RunID             string
	BatchesRun        int
	AnalysisCount     int
	FindingCount      int
	ErrorBatchCount   int
	QuotaExhausted    bool
	BudgetExhausted   bool
	TotalCostUSD      float64
	TotalInputTokens  uint64
	TotalOutputTokens uint64
	TotalDurationMs   uint64
}

// Process runs the AI-investigation pipeline over a project's
// FileRecords. Concurrency is bounded by opts.Concurrency; quota errors
// flip a shared cancel flag so in-flight batches stop cleanly.
func Process(ctx context.Context, opts ProcessOptions) (*ProcessOutcome, error) {
	runID := core.GenerateRunID()
	directMode := len(opts.DirectFiles) > 0
	invocationMode := core.InvocationModeScan
	if directMode {
		invocationMode = core.InvocationModeDirect
	}
	meta := core.NewRunMeta(opts.ProjectID, runID, opts.ProjectRoot, core.RunTypeProcess)
	meta.ProcessorConfig = &core.ProcessorConfig{
		AgentType:      opts.ProviderName,
		Model:          opts.Backend.Model(),
		ModelConfig:    opts.ModelSettings.AsMap(),
		InvocationMode: invocationMode,
		Source:         opts.DirectSource,
	}
	if err := opts.DataRoot.WriteRunMeta(meta); err != nil {
		return nil, err
	}

	records, err := opts.DataRoot.LoadAllFileRecords(opts.ProjectID)
	if err != nil {
		return nil, err
	}

	work := filterWork(records, opts, directMode)
	if opts.Limit > 0 && len(work) > opts.Limit {
		work = work[:opts.Limit]
	}

	techTags := []string{}
	if opts.Detected != nil {
		techTags = opts.Detected.Tags
	}

	batches := scanner.BatchRecords(work, batchSize(opts.BatchSize))
	outcome := &ProcessOutcome{
		RunID:      runID,
		BatchesRun: len(batches),
	}

	// Lock everything up front so a parallel run won't claim the same
	// files. Lock failure is non-fatal — log and continue.
	now := core.NowISO()
	for _, batch := range batches {
		for _, r := range batch {
			rec, err := opts.DataRoot.ReadFileRecord(opts.ProjectID, r.FilePath)
			if err != nil || rec == nil {
				continue
			}
			rec.Status = core.StatusProcessing
			rec.LockedByRunID = runID
			rec.LockedAt = now
			_ = opts.DataRoot.WriteFileRecord(rec)
		}
	}

	sem := semaphore.NewWeighted(int64(maxConcurrency(opts.Concurrency)))
	cancelCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	g, ggCtx := errgroup.WithContext(cancelCtx)

	var mu sync.Mutex
	type batchResult struct {
		paths   []string
		out     *InvestigateOutput
		quotaed bool
		failed  bool
		errMsg  string
	}
	results := make([]batchResult, len(batches))

	for i, batch := range batches {
		i, batch := i, batch
		paths := make([]string, len(batch))
		for j, r := range batch {
			paths[j] = r.FilePath
		}
		ibatch := buildInvestigateBatch(opts.ProjectRoot, batch, techTags, opts.ProjectInfo, opts.PromptAppend)
		ibatch.ToolsEnabled = opts.ToolsEnabled
		ibatch.MaxTurns = opts.MaxTurns
		ibatch.MaxCostUSD = opts.MaxCostUSD
		g.Go(func() error {
			if err := sem.Acquire(ggCtx, 1); err != nil {
				// Context cancelled before we got a permit — treat as
				// cancelled, not as an error. Locks go back to pending.
				results[i] = batchResult{paths: paths, quotaed: true}
				return nil
			}
			defer sem.Release(1)
			out, err := opts.Backend.Investigate(ggCtx, ibatch)
			if err != nil {
				if IsQuotaErr(err) {
					mu.Lock()
					outcome.QuotaExhausted = true
					mu.Unlock()
					cancel()
					results[i] = batchResult{paths: paths, quotaed: true}
					return nil
				}
				// A cancelled context (sibling batch quotaed-out, or the
				// caller cancelled) shouldn't downgrade these files to
				// status=error; release them back to pending instead.
				if errors.Is(err, context.Canceled) {
					results[i] = batchResult{paths: paths, quotaed: true}
					return nil
				}
				results[i] = batchResult{paths: paths, failed: true, errMsg: err.Error()}
				return nil
			}
			mu.Lock()
			outcome.TotalCostUSD += out.CostUSD
			outcome.TotalInputTokens += out.Usage.InputTokens
			outcome.TotalOutputTokens += out.Usage.OutputTokens
			outcome.TotalDurationMs += out.DurationMs
			if opts.MaxCostUSD > 0 && outcome.TotalCostUSD >= opts.MaxCostUSD {
				outcome.BudgetExhausted = true
				cancel()
			}
			mu.Unlock()
			results[i] = batchResult{paths: paths, out: out}
			return nil
		})
	}
	_ = g.Wait()

	// Apply results sequentially so concurrent writers can't fight over
	// the same FileRecord. The order is deterministic and parsing-cheap.
	for _, r := range results {
		switch {
		case r.quotaed:
			outcome.ErrorBatchCount++
			releaseLocks(opts.DataRoot, opts.ProjectID, r.paths, core.StatusPending)
		case r.failed:
			outcome.ErrorBatchCount++
			releaseLocks(opts.DataRoot, opts.ProjectID, r.paths, core.StatusError)
		case r.out == nil:
			// cancelled before dispatch; release back to pending
			releaseLocks(opts.DataRoot, opts.ProjectID, r.paths, core.StatusPending)
		default:
			if opts.SkepticEnabled {
				if cost, err := applySkeptic(ctx, opts, r.out); err == nil {
					outcome.TotalCostUSD += cost
					if opts.MaxCostUSD > 0 && outcome.TotalCostUSD >= opts.MaxCostUSD {
						outcome.BudgetExhausted = true
					}
				}
			}
			applied := applyBatch(opts, runID, r.paths, r.out)
			outcome.AnalysisCount += applied.analyzed
			outcome.FindingCount += applied.findings
		}
	}

	fp := outcome.AnalysisCount
	meta.Stats.FilesProcessed = &fp
	meta.Stats.FindingsCount = &outcome.FindingCount
	meta.Stats.TotalInputTokens = &outcome.TotalInputTokens
	meta.Stats.TotalOutputTokens = &outcome.TotalOutputTokens
	meta.Stats.TotalCostUSD = &outcome.TotalCostUSD
	meta.Stats.TotalDurationMs = &outcome.TotalDurationMs
	if err := opts.DataRoot.WriteRunMeta(meta); err != nil {
		return nil, err
	}
	phase := core.RunPhaseDone
	if outcome.ErrorBatchCount > 0 && outcome.AnalysisCount == 0 {
		phase = core.RunPhaseError
	}
	if _, err := opts.DataRoot.CompleteRun(opts.ProjectID, runID, phase); err != nil {
		return nil, err
	}
	return outcome, nil
}

type applyStats struct {
	analyzed int
	findings int
}

func applyBatch(opts ProcessOptions, runID string, paths []string, out *InvestigateOutput) applyStats {
	stats := applyStats{}
	n := len(paths)
	if n == 0 {
		return stats
	}
	perCost := out.CostUSD / float64(n)
	perUsage := core.Usage{
		InputTokens:              out.Usage.InputTokens / uint64(n),
		OutputTokens:             out.Usage.OutputTokens / uint64(n),
		CacheReadInputTokens:     out.Usage.CacheReadInputTokens / uint64(n),
		CacheCreationInputTokens: out.Usage.CacheCreationInputTokens / uint64(n),
	}
	perDur := out.DurationMs / uint64(n)

	byFile := map[string][]ProducedFinding{}
	for _, r := range out.Results {
		byFile[r.FilePath] = r.Findings
	}

	for _, path := range paths {
		rec, err := opts.DataRoot.ReadFileRecord(opts.ProjectID, path)
		if err != nil || rec == nil {
			continue
		}
		findings := byFile[path]
		if out.Refusal != nil {
			rec.AnalysisHistory = append(rec.AnalysisHistory, core.AnalysisEntry{
				RunID:          runID,
				InvestigatedAt: core.NowISO(),
				DurationMs:     perDur,
				AgentType:      opts.ProviderName,
				Model:          opts.Backend.Model(),
				ModelConfig:    opts.ModelSettings.AsMap(),
				FindingCount:   0,
				Phase:          core.PhaseProcess,
				CostUSD:        ptr(perCost),
				Usage:          &perUsage,
				Refusal:        out.Refusal,
			})
			rec.Status = core.StatusError
			rec.LockedByRunID = ""
			rec.LockedAt = ""
			_ = opts.DataRoot.WriteFileRecord(rec)
			continue
		}
		appendFindings(rec, runID, findings)
		entry := core.AnalysisEntry{
			RunID:          runID,
			InvestigatedAt: core.NowISO(),
			DurationMs:     perDur,
			AgentType:      opts.ProviderName,
			Model:          opts.Backend.Model(),
			ModelConfig:    opts.ModelSettings.AsMap(),
			FindingCount:   len(findings),
			NumTurns:       intPtr(out.NumTurns),
			Phase:          core.PhaseProcess,
			CostUSD:        ptr(perCost),
			Usage:          &perUsage,
		}
		if opts.ReinvestigateMark > 0 {
			entry.ReinvestigateMark = intPtr(opts.ReinvestigateMark)
		}
		rec.AnalysisHistory = append(rec.AnalysisHistory, entry)
		rec.Status = core.StatusAnalyzed
		rec.LockedByRunID = ""
		rec.LockedAt = ""
		stats.findings += len(findings)
		stats.analyzed++
		_ = opts.DataRoot.WriteFileRecord(rec)
	}
	return stats
}

func appendFindings(rec *core.FileRecord, runID string, findings []ProducedFinding) {
	seen := map[string]bool{}
	for _, f := range rec.Findings {
		seen[f.VulnSlug+"|"+f.Title] = true
	}
	for _, f := range findings {
		key := f.VulnSlug + "|" + f.Title
		if seen[key] {
			continue
		}
		seen[key] = true
		rec.Findings = append(rec.Findings, core.Finding{
			Severity:        f.Severity,
			VulnSlug:        f.VulnSlug,
			Title:           f.Title,
			Description:     f.Description,
			LineNumbers:     f.LineNumbers,
			Recommendation:  f.Recommendation,
			Confidence:      f.Confidence,
			ProducedByRunID: runID,
		})
	}
}

func releaseLocks(root core.DataRoot, projectID string, paths []string, status core.FileStatus) {
	for _, p := range paths {
		rec, err := root.ReadFileRecord(projectID, p)
		if err != nil || rec == nil {
			continue
		}
		rec.Status = status
		rec.LockedByRunID = ""
		rec.LockedAt = ""
		_ = root.WriteFileRecord(rec)
	}
}

func filterWork(records []*core.FileRecord, opts ProcessOptions, directMode bool) []*core.FileRecord {
	onlySet := toStringSet(opts.OnlySlugs)
	skipSet := toStringSet(opts.SkipSlugs)
	directSet := toStringSet(opts.DirectFiles)

	out := make([]*core.FileRecord, 0)
	for _, r := range records {
		if directMode {
			if _, ok := directSet[r.FilePath]; !ok {
				continue
			}
		} else {
			if len(r.Candidates) == 0 {
				continue
			}
			if r.Status != core.StatusPending && r.Status != core.StatusError {
				continue
			}
		}
		if opts.FilterPrefix != "" && !hasPrefix(r.FilePath, opts.FilterPrefix) {
			continue
		}
		if len(onlySet) > 0 && !hasAny(r.Candidates, onlySet) {
			continue
		}
		if len(skipSet) > 0 && allIn(r.Candidates, skipSet) {
			continue
		}
		if opts.ReinvestigateMark > 0 && hasWave(r, opts.ReinvestigateMark, opts.ProviderName) {
			continue
		}
		out = append(out, r)
	}
	sort.SliceStable(out, func(i, j int) bool {
		ai, aj := len(out[i].Candidates) == 0, len(out[j].Candidates) == 0
		if ai != aj {
			return !ai
		}
		return out[i].FilePath < out[j].FilePath
	})
	return out
}

func hasWave(r *core.FileRecord, wave int, agent string) bool {
	for _, e := range r.AnalysisHistory {
		if e.ReinvestigateMark != nil && *e.ReinvestigateMark == wave &&
			e.AgentType == agent && e.Phase != core.PhaseRevalidate {
			return true
		}
	}
	return false
}

func hasAny(cs []core.CandidateMatch, set map[string]struct{}) bool {
	for _, c := range cs {
		if _, ok := set[c.VulnSlug]; ok {
			return true
		}
	}
	return false
}

func allIn(cs []core.CandidateMatch, set map[string]struct{}) bool {
	for _, c := range cs {
		if _, ok := set[c.VulnSlug]; !ok {
			return false
		}
	}
	return true
}

func toStringSet(xs []string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, x := range xs {
		if x != "" {
			out[x] = struct{}{}
		}
	}
	return out
}

func hasPrefix(s, p string) bool {
	return len(s) >= len(p) && s[:len(p)] == p
}

func buildInvestigateBatch(root string, batch []*core.FileRecord, techTags []string, info, append_ string) *InvestigateBatch {
	files := make([]InvestigateFile, 0, len(batch))
	slugSet := map[string]struct{}{}
	for _, r := range batch {
		body, _ := os.ReadFile(filepath.Join(root, r.FilePath))
		for _, c := range r.Candidates {
			slugSet[c.VulnSlug] = struct{}{}
		}
		files = append(files, InvestigateFile{
			Path:       r.FilePath,
			Content:    string(body),
			Candidates: r.Candidates,
		})
	}
	slugs := make([]string, 0, len(slugSet))
	for k := range slugSet {
		slugs = append(slugs, k)
	}
	return &InvestigateBatch{
		ProjectRoot:  root,
		Files:        files,
		ProjectInfo:  info,
		PromptAppend: append_,
		TechTags:     techTags,
		SlugNotes:    slugs,
	}
}

func batchSize(n int) int {
	if n < 1 {
		return 5
	}
	return n
}

func maxConcurrency(n int) int {
	if n < 1 {
		return 4
	}
	return n
}

func ptr(f float64) *float64 { return &f }
func intPtr(i int) *int      { return &i }

// LoadAllFileRecords is exposed here so the CLI can reuse it without
// importing core directly for one read path.
func LoadAllFileRecords(root core.DataRoot, projectID string) ([]*core.FileRecord, error) {
	out, err := root.LoadAllFileRecords(projectID)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("loading file records: %w", err)
	}
	return out, nil
}
