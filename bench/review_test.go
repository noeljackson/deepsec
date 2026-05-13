package bench

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

type noopEditor struct{}

func (noopEditor) Run(path string) error { return nil }

func TestReviewReadonlySSRFSnapshot(t *testing.T) {
	var out bytes.Buffer
	err := RunReview(ReviewOptions{
		Slug:     "ssrf",
		TasksDir: "tasks",
		OutDir:   filepath.Join(t.TempDir(), "out"),
		Out:      &out,
	})
	require.NoError(t, err)
	require.Equal(t, `=== ssrf (precision 1.00, recall 1.00) ===

False positives (0):
  none

False negatives (0):
  none
`, out.String())
}

func TestReviewRescoreSameMatchersHasNoFalseImprovement(t *testing.T) {
	opts := ReviewOptions{Slug: "ssrf", TasksDir: "tasks", OutDir: filepath.Join(t.TempDir(), "out")}
	first, err := scoreSlug(opts, nil)
	require.NoError(t, err)
	second, err := scoreSlug(opts, nil)
	require.NoError(t, err)

	require.True(t, reviewsEqual(first, second))
	require.False(t, metricsImproved(first.Metrics, second.Metrics))
}

func TestReviewEmitFPsIsJSONList(t *testing.T) {
	var out bytes.Buffer
	err := RunReview(ReviewOptions{
		Slug:     "ssrf",
		TasksDir: "tasks",
		OutDir:   filepath.Join(t.TempDir(), "out"),
		EmitFPs:  true,
		Out:      &out,
	})
	require.NoError(t, err)
	require.Equal(t, "[]\n", out.String())
}

func TestReviewNoopEditReportsNoMetricDeltaAndCommitRequiresAcceptedEdit(t *testing.T) {
	tmp := t.TempDir()
	var out bytes.Buffer
	err := RunReview(ReviewOptions{
		Slug:     "ssrf",
		TasksDir: "tasks",
		OutDir:   filepath.Join(tmp, "out"),
		Edit:     true,
		Out:      &out,
		Editor:   noopEditor{},
	})
	require.NoError(t, err)
	require.Contains(t, out.String(), "Old: precision 1.00, recall 1.00, FP count 0, FN count 0")
	require.Contains(t, out.String(), "New: precision 1.00, recall 1.00, FP count 0, FN count 0")
	require.Contains(t, out.String(), "No metric delta; nothing to accept.")

	err = RunReview(ReviewOptions{
		Slug:          "ssrf",
		TasksDir:      "tasks",
		OutDir:        filepath.Join(tmp, "out"),
		CommitMessage: "test commit",
		Out:           &bytes.Buffer{},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "requires a prior accepted --edit")
}
