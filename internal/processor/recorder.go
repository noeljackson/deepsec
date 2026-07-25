package processor

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/noeljackson/deepsec/internal/core"
	"github.com/noeljackson/deepsec/internal/processor/providers"
)

// RecordingBackend wraps an AgentBackend and tees every Investigate
// (batch, output) pair into a JSONL file in dispatch order. The format
// matches what `internal/processor/mockbackend.Backend` replays:
//
//	{"batchPaths":[...], "output":{...InvestigateOutput...}}
//
// Used by `deepsec process --record <path>` to capture a real backend
// run as a frozen fixture under `bench/processor-fixtures/<task>/`.
//
// Revalidate and Triage pass through unchanged — only Investigate is
// recorded, because the replay scorer only exercises investigation.
type RecordingBackend struct {
	inner AgentBackend
	mu    sync.Mutex
	f     *os.File
	enc   *json.Encoder
}

// NewRecordingBackend opens `path` for write (truncating any existing
// content) and returns a backend that records every Investigate result
// alongside calls to `inner`. Close must be invoked when the run
// finishes (or errors) to flush the file.
func NewRecordingBackend(inner AgentBackend, path string) (*RecordingBackend, error) {
	if path == "" {
		return nil, fmt.Errorf("recorder: empty path")
	}
	if err := os.MkdirAll(dirOf(path), 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dirOf(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	return &RecordingBackend{
		inner: inner,
		f:     f,
		enc:   json.NewEncoder(f),
	}, nil
}

// Close flushes and closes the underlying file. Safe to call more than
// once.
func (r *RecordingBackend) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return nil
	}
	err := r.f.Close()
	r.f = nil
	return err
}

func (r *RecordingBackend) Kind() providers.Kind { return r.inner.Kind() }
func (r *RecordingBackend) Model() string        { return r.inner.Model() }

func (r *RecordingBackend) Investigate(ctx context.Context, batch *InvestigateBatch) (*InvestigateOutput, error) {
	out, err := r.inner.Investigate(ctx, batch)
	if err != nil {
		// Don't write malformed records. The replay scorer expects every
		// line to be a successful batch.
		return out, err
	}
	if err := r.writeRecord(batch, out); err != nil {
		return out, fmt.Errorf("recorder: %w", err)
	}
	return out, nil
}

func (r *RecordingBackend) Revalidate(ctx context.Context, in *RevalidateInput) ([]RevalidatedFinding, core.Usage, uint64, error) {
	return r.inner.Revalidate(ctx, in)
}

func (r *RecordingBackend) Triage(ctx context.Context, in *TriageInput) (*TriagedFinding, core.Usage, uint64, error) {
	return r.inner.Triage(ctx, in)
}

// recordedBatch is the on-disk wire shape; field tags match the
// mockbackend.RecordedResponse so round-trip replay is byte-faithful.
type recordedBatch struct {
	BatchPaths []string           `json:"batchPaths"`
	Output     *InvestigateOutput `json:"output"`
}

func (r *RecordingBackend) writeRecord(batch *InvestigateBatch, out *InvestigateOutput) error {
	paths := make([]string, len(batch.Files))
	for i, f := range batch.Files {
		paths[i] = f.Path
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return fmt.Errorf("recorder closed")
	}
	return r.enc.Encode(&recordedBatch{BatchPaths: paths, Output: redactInvestigateOutput(out)})
}

func redactInvestigateOutput(out *InvestigateOutput) *InvestigateOutput {
	if out == nil {
		return nil
	}
	copy := *out
	copy.Results = make([]InvestigateResult, len(out.Results))
	for i, result := range out.Results {
		resultCopy := result
		resultCopy.Findings = make([]ProducedFinding, len(result.Findings))
		for j, finding := range result.Findings {
			finding.Title = core.RedactSecrets(finding.Title)
			finding.Description = core.RedactSecrets(finding.Description)
			finding.Recommendation = core.RedactSecrets(finding.Recommendation)
			resultCopy.Findings[j] = finding
		}
		copy.Results[i] = resultCopy
	}
	if out.Refusal != nil {
		refusal := *out.Refusal
		refusal.Reason = core.RedactSecrets(refusal.Reason)
		refusal.Raw = core.RedactSecrets(refusal.Raw)
		copy.Refusal = &refusal
	}
	return &copy
}

func dirOf(path string) string { return filepath.Dir(path) }
