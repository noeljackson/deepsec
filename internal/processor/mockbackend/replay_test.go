package mockbackend

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/noeljackson/deepsec/internal/processor"
	"github.com/stretchr/testify/require"
)

func writeResponses(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "responses.jsonl")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o644))
	return path
}

func TestReplayMatchesBatch(t *testing.T) {
	path := writeResponses(t, `{"batchPaths":["src/a.ts"],"output":{"results":[{"filePath":"src/a.ts","findings":[{"severity":"HIGH","vulnSlug":"ssrf","title":"t","lineNumbers":[1],"confidence":"high"}]}],"costUsd":12.5}}`+"\n")
	b, err := New(path)
	require.NoError(t, err)

	out, err := b.Investigate(context.Background(), &processor.InvestigateBatch{Files: []processor.InvestigateFile{{Path: "src/a.ts"}}})
	require.NoError(t, err)
	require.Equal(t, 0.0, out.CostUSD)
	require.Len(t, out.Results, 1)
	require.Equal(t, "src/a.ts", out.Results[0].FilePath)
	require.Equal(t, 1, b.Consumed())
}

func TestReplayErrorsOnMismatch(t *testing.T) {
	path := writeResponses(t, `{"batchPaths":["src/a.ts"],"output":{"results":[]}}`+"\n")
	b, err := New(path)
	require.NoError(t, err)

	_, err = b.Investigate(context.Background(), &processor.InvestigateBatch{Files: []processor.InvestigateFile{{Path: "src/b.ts"}}})
	require.ErrorContains(t, err, "expected batch [src/a.ts] at position 1, got [src/b.ts]")
}

func TestReplayErrorsOnExhaustedResponses(t *testing.T) {
	path := writeResponses(t, `{"batchPaths":["src/a.ts"],"output":{"results":[]}}`+"\n")
	b, err := New(path)
	require.NoError(t, err)
	_, err = b.Investigate(context.Background(), &processor.InvestigateBatch{Files: []processor.InvestigateFile{{Path: "src/a.ts"}}})
	require.NoError(t, err)

	_, err = b.Investigate(context.Background(), &processor.InvestigateBatch{Files: []processor.InvestigateFile{{Path: "src/b.ts"}}})
	require.ErrorContains(t, err, "responses exhausted")
}

func TestReplayErrorsOnMalformedJSONL(t *testing.T) {
	path := writeResponses(t, `{"batchPaths":["src/a.ts"],"output":{"results":[]}}`+"\n"+"not-json\n")
	_, err := New(path)
	require.ErrorContains(t, err, "malformed response JSONL")
}
