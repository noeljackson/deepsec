package bench

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProcessScoreStarterFixtures(t *testing.T) {
	result, err := ProcessScore(nil, ProcessScoreOptions{
		TasksDir: "processor-fixtures",
		OutDir:   filepath.Join(t.TempDir(), "out"),
		Now:      "20260101T000000Z",
	})
	require.NoError(t, err)

	require.Equal(t, 2, result.Summary.TaskCount)
	require.Equal(t, 1.0, result.Summary.ProcessorPrecision)
	require.Equal(t, 1.0, result.Summary.ProcessorRecallGivenCandidate)
	require.Equal(t, 1.0, result.Summary.ProcessorRecall)
	require.Equal(t, 1.0, result.Summary.SeverityAccuracy)
	require.Equal(t, 0.5, result.Summary.RefusalRate)
	require.Equal(t, 0, result.Summary.FalsePositiveCount)
	require.Equal(t, 0, result.Summary.FalseNegativeCount)
	require.Equal(t, 1.0, result.Summary.PerSlugPrecision["ssrf"])
	require.Equal(t, 1.0, result.Summary.PerSlugRecall["ssrf"])

	require.FileExists(t, filepath.Join(result.Summary.OutputDir, "summary.json"))
	require.FileExists(t, filepath.Join(result.Summary.OutputDir, "by_task.tsv"))
	require.FileExists(t, filepath.Join(result.Summary.OutputDir, "by_slug.tsv"))
	require.FileExists(t, filepath.Join(result.Summary.OutputDir, "false_positives.json"))
	require.FileExists(t, filepath.Join(result.Summary.OutputDir, "false_negatives.json"))
	require.FileExists(t, filepath.Join(result.Summary.OutputDir, "severity_mismatches.json"))
}

func TestProcessAnswerValidationRejectsMalformed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "answer.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
findings:
  - id: bad
    file: ../src/fetch.ts
    vulnSlugs: []
    severity: HIGH
    location: { startLine: 4, endLine: 2 }
    processor: { mustReportFinding: true }
`), 0o644))
	_, err := loadProcessorAnswerKey(path)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid filePath")
}

func TestProcessScoreReportsAreDeterministic(t *testing.T) {
	outDir := filepath.Join(t.TempDir(), "out")
	opts := ProcessScoreOptions{TasksDir: "processor-fixtures", OutDir: outDir, Now: "20260101T000000Z"}
	first, err := ProcessScore(nil, opts)
	require.NoError(t, err)
	firstReports := readReportFiles(t, first.Summary.OutputDir)

	second, err := ProcessScore(nil, opts)
	require.NoError(t, err)
	require.Equal(t, first.CanonicalReports(), second.CanonicalReports())
	require.Equal(t, firstReports, readReportFiles(t, second.Summary.OutputDir))
}

func readReportFiles(t *testing.T, dir string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	out := map[string]string{}
	for _, name := range names {
		body, err := os.ReadFile(filepath.Join(dir, name))
		require.NoError(t, err)
		out[name] = string(body)
	}
	return out
}
