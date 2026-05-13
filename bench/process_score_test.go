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

func TestProcessScoreRepeatedDeterministicFixturesAreByteIdentical(t *testing.T) {
	optsA := ProcessScoreOptions{
		TasksDir: "processor-fixtures", OutDir: filepath.Join(t.TempDir(), "out-a"),
		Now: "20260101T000000Z", Repeat: 10, Seed: 1, BootstrapSamples: 1000,
	}
	first, err := ProcessScoreRepeated(nil, optsA)
	require.NoError(t, err)
	optsB := optsA
	optsB.OutDir = filepath.Join(t.TempDir(), "out-b")
	second, err := ProcessScoreRepeated(nil, optsB)
	require.NoError(t, err)

	firstBody, err := os.ReadFile(filepath.Join(optsA.OutDir, optsA.Now, "summary-repeated.json"))
	require.NoError(t, err)
	secondBody, err := os.ReadFile(filepath.Join(optsB.OutDir, optsB.Now, "summary-repeated.json"))
	require.NoError(t, err)
	require.Equal(t, firstBody, secondBody)
	require.Equal(t, 0.0, first.Metrics["processor_precision"].Stddev)
	require.Equal(t, 0.0, second.Metrics["processor_precision"].CIHigh-second.Metrics["processor_precision"].CILow)
}

func TestProcessScoreRepeatedStochasticFixtureHasNonZeroCI(t *testing.T) {
	outDir := filepath.Join(t.TempDir(), "out")
	result, err := ProcessScoreRepeated(nil, ProcessScoreOptions{
		TasksDir: "processor-stochastic-fixtures", OutDir: outDir,
		Now: "20260101T000000Z", Repeat: 30, Seed: 1, BootstrapSamples: 1000,
	})
	require.NoError(t, err)
	metric := result.Metrics["processor_recall"]
	require.Greater(t, metric.CIHigh-metric.CILow, 0.0)
	require.FileExists(t, filepath.Join(outDir, "20260101T000000Z", "summary-repeated.json"))
}

func TestProcessCompareVerdicts(t *testing.T) {
	tmp := t.TempDir()
	aDir := filepath.Join(tmp, "a")
	bDir := filepath.Join(tmp, "b")
	cDir := filepath.Join(tmp, "c")
	require.NoError(t, os.MkdirAll(aDir, 0o755))
	require.NoError(t, os.MkdirAll(bDir, 0o755))
	require.NoError(t, os.MkdirAll(cDir, 0o755))

	writeRepeatedSummary(t, aDir, []float64{0.45, 0.46, 0.47, 0.48, 0.49})
	writeRepeatedSummary(t, bDir, []float64{0.80, 0.81, 0.82, 0.83, 0.84})
	writeRepeatedSummary(t, cDir, []float64{0.44, 0.45, 0.46, 0.47, 0.48})

	improved, err := ProcessCompare(aDir, bDir, ProcessCompareOptions{Seed: 1, BootstrapSamples: 1000})
	require.NoError(t, err)
	require.Equal(t, "improved", improved.Metrics[0].Verdict)
	require.FileExists(t, filepath.Join(bDir, "process-compare.tsv"))
	require.FileExists(t, filepath.Join(bDir, "process-compare.json"))

	overlap, err := ProcessCompare(aDir, cDir, ProcessCompareOptions{Seed: 1, BootstrapSamples: 1000})
	require.NoError(t, err)
	require.Equal(t, "inconclusive", overlap.Metrics[0].Verdict)
}

func TestBootstrapReproducible(t *testing.T) {
	first := summarizeRepeatedSample([]float64{0, 1, 0, 1, 1, 0}, 1000, 42)
	second := summarizeRepeatedSample([]float64{0, 1, 0, 1, 1, 0}, 1000, 42)
	require.Equal(t, first.CILow, second.CILow)
	require.Equal(t, first.CIHigh, second.CIHigh)
}

func writeRepeatedSummary(t *testing.T, dir string, samples []float64) {
	t.Helper()
	body := ProcessRepeatedResult{
		GeneratedAt:      "20260101T000000Z",
		Repeat:           len(samples),
		Seed:             1,
		BootstrapSamples: 1000,
		Metrics: map[string]RepeatedMetric{
			"processor_precision": summarizeRepeatedSample(samples, 1000, 1),
		},
	}
	require.NoError(t, writeJSON(filepath.Join(dir, "summary-repeated.json"), body))
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
