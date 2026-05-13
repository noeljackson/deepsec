package processor_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/noeljackson/deepsec/internal/core"
	"github.com/noeljackson/deepsec/internal/processor"
	"github.com/noeljackson/deepsec/internal/processor/mockbackend"
	"github.com/noeljackson/deepsec/internal/processor/providers"
	"github.com/stretchr/testify/require"
)

// scriptedBackend produces a recorded, deterministic finding for each
// file in every batch. Used to exercise the recorder without standing
// up a real LLM.
type scriptedBackend struct{}

func (scriptedBackend) Kind() providers.Kind { return providers.KindAnthropic }
func (scriptedBackend) Model() string        { return "scripted-model" }

func (scriptedBackend) Investigate(ctx context.Context, batch *processor.InvestigateBatch) (*processor.InvestigateOutput, error) {
	out := &processor.InvestigateOutput{
		Usage:      core.Usage{InputTokens: 100, OutputTokens: 20},
		DurationMs: 5,
		NumTurns:   1,
		CostUSD:    0.001,
	}
	for _, f := range batch.Files {
		out.Results = append(out.Results, processor.InvestigateResult{
			FilePath: f.Path,
			Findings: []processor.ProducedFinding{{
				Severity:       core.SeverityHigh,
				VulnSlug:       "scripted-finding",
				Title:          "scripted",
				Description:    "deterministic finding for " + f.Path,
				LineNumbers:    []int{1},
				Recommendation: "no-op",
				Confidence:     core.ConfidenceHigh,
			}},
		})
	}
	return out, nil
}

func (scriptedBackend) Revalidate(context.Context, *processor.RevalidateInput) ([]processor.RevalidatedFinding, core.Usage, uint64, error) {
	return nil, core.Usage{}, 0, nil
}

func (scriptedBackend) Triage(context.Context, *processor.TriageInput) (*processor.TriagedFinding, core.Usage, uint64, error) {
	return nil, core.Usage{}, 0, nil
}

func TestRecordingBackendRoundTripsThroughReplay(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "responses.jsonl")
	rec, err := processor.NewRecordingBackend(scriptedBackend{}, path)
	require.NoError(t, err)

	// Two batches; the recorder should preserve dispatch order.
	for _, paths := range [][]string{{"src/a.ts", "src/b.ts"}, {"src/c.ts"}} {
		files := make([]processor.InvestigateFile, len(paths))
		for i, p := range paths {
			files[i] = processor.InvestigateFile{Path: p, Content: "// " + p}
		}
		_, err := rec.Investigate(context.Background(), &processor.InvestigateBatch{Files: files})
		require.NoError(t, err)
	}
	require.NoError(t, rec.Close())

	// Replaying the recorded file through the mock backend must hand
	// back the exact same outputs in the same order.
	replay, err := mockbackend.New(path)
	require.NoError(t, err)
	require.Equal(t, 2, replay.TotalResponses())

	for _, paths := range [][]string{{"src/a.ts", "src/b.ts"}, {"src/c.ts"}} {
		files := make([]processor.InvestigateFile, len(paths))
		for i, p := range paths {
			files[i] = processor.InvestigateFile{Path: p}
		}
		out, err := replay.Investigate(context.Background(), &processor.InvestigateBatch{Files: files})
		require.NoError(t, err)
		require.Len(t, out.Results, len(paths), "batch %v", paths)
		for i, r := range out.Results {
			require.Equal(t, paths[i], r.FilePath)
			require.Len(t, r.Findings, 1)
			require.Equal(t, "scripted-finding", r.Findings[0].VulnSlug)
		}
	}
	require.Equal(t, 2, replay.Consumed())
}

func TestRecordingBackendSkipsFailedBatches(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "responses.jsonl")
	rec, err := processor.NewRecordingBackend(failingBackend{}, path)
	require.NoError(t, err)
	_, err = rec.Investigate(context.Background(), &processor.InvestigateBatch{
		Files: []processor.InvestigateFile{{Path: "x"}},
	})
	require.Error(t, err)
	require.NoError(t, rec.Close())

	// An empty JSONL is valid; replay should report zero recorded responses.
	replay, err := mockbackend.New(path)
	require.NoError(t, err)
	require.Equal(t, 0, replay.TotalResponses())
}

type failingBackend struct{ scriptedBackend }

func (failingBackend) Investigate(context.Context, *processor.InvestigateBatch) (*processor.InvestigateOutput, error) {
	return nil, &processor.QuotaExhaustedError{Provider: "fake", Detail: "boom"}
}
