package scanner

import (
	"testing"

	"github.com/noeljackson/deepsec/internal/core"
	"github.com/stretchr/testify/require"
)

func TestDetectTechTagsNodeTypeScript(t *testing.T) {
	d := t.TempDir()
	writeFile(t, d, "package.json", `{"name":"x","dependencies":{"typescript":"^5","react":"^18"}}`)
	writeFile(t, d, "tsconfig.json", "{}")
	tech := Detect(d)
	require.Contains(t, tech.Tags, "node")
	require.Contains(t, tech.Tags, "typescript")
	require.Contains(t, tech.Tags, "react")
}

func TestDetectTechTagsNextjs(t *testing.T) {
	d := t.TempDir()
	writeFile(t, d, "package.json", `{"name":"x","dependencies":{"next":"^14"}}`)
	tech := Detect(d)
	require.Contains(t, tech.Tags, "nextjs")
	require.Contains(t, tech.Tags, "node")
}

func TestDetectTechTagsRustAxum(t *testing.T) {
	d := t.TempDir()
	writeFile(t, d, "Cargo.toml", `[package]
name = "x"
[dependencies]
axum = "0.7"`)
	tech := Detect(d)
	require.Contains(t, tech.Tags, "rust")
	require.Contains(t, tech.Tags, "axum")
}

func TestDetectTechTagsPythonDjango(t *testing.T) {
	d := t.TempDir()
	writeFile(t, d, "requirements.txt", "Django==5.0\nrequests==2.31\n")
	tech := Detect(d)
	require.Contains(t, tech.Tags, "python")
	require.Contains(t, tech.Tags, "django")
}

func TestDetectTechEmptyForUnknown(t *testing.T) {
	d := t.TempDir()
	writeFile(t, d, "src/a.txt", "hello")
	tech := Detect(d)
	for _, tag := range tech.Tags {
		require.NotContains(t, []string{"nextjs", "django", "rails"}, tag)
	}
}

func TestEvaluateGateEmptyAlwaysPasses(t *testing.T) {
	require.True(t, EvaluateGate(MatcherGate{}, DetectedTech{}, "."))
}

func TestEvaluateGateTechMatch(t *testing.T) {
	require.True(t, EvaluateGate(
		MatcherGate{Tech: []string{"nextjs"}},
		DetectedTech{Tags: []string{"nextjs"}},
		".",
	))
}

func TestEvaluateGateTechNoMatch(t *testing.T) {
	require.False(t, EvaluateGate(
		MatcherGate{Tech: []string{"nextjs"}},
		DetectedTech{Tags: []string{"django"}},
		".",
	))
}

func TestEvaluateGateSentinelFilePresentPasses(t *testing.T) {
	d := t.TempDir()
	writeFile(t, d, "package.json", "{}")
	require.True(t, EvaluateGate(
		MatcherGate{SentinelFiles: []string{"package.json"}},
		DetectedTech{},
		d,
	))
}

func TestEvaluateGateSentinelContainsMatch(t *testing.T) {
	d := t.TempDir()
	writeFile(t, d, "Cargo.toml", "[dependencies]\naxum = \"0.7\"\n")
	require.True(t, EvaluateGate(
		MatcherGate{
			SentinelFiles:    []string{"Cargo.toml"},
			SentinelContains: []string{"axum"},
		},
		DetectedTech{},
		d,
	))
}

func TestEvaluateGateSentinelContainsMiss(t *testing.T) {
	d := t.TempDir()
	writeFile(t, d, "Cargo.toml", "[dependencies]\nserde = \"1\"\n")
	require.False(t, EvaluateGate(
		MatcherGate{
			SentinelFiles:    []string{"Cargo.toml"},
			SentinelContains: []string{"axum"},
		},
		DetectedTech{},
		d,
	))
}

func TestEvaluateGateUnion(t *testing.T) {
	d := t.TempDir()
	writeFile(t, d, "package.json", "{}")
	// tech misses, but sentinel matches → gate passes
	require.True(t, EvaluateGate(
		MatcherGate{
			Tech:          []string{"nonexistent"},
			SentinelFiles: []string{"package.json"},
		},
		DetectedTech{Tags: []string{"something-else"}},
		d,
	))
}

func mkRec(path string) *core.FileRecord {
	return &core.FileRecord{
		FilePath:         path,
		ProjectID:        "p",
		Candidates:       []core.CandidateMatch{{VulnSlug: "s", LineNumbers: []int{1}}},
		LastScannedAt:    "2026-01-01T00:00:00Z",
		LastScannedRunID: "r",
		FileHash:         "h",
		Status:           core.StatusPending,
	}
}

func TestBatchRecordsGroupsByDirectory(t *testing.T) {
	recs := []*core.FileRecord{
		mkRec("src/api/a.ts"),
		mkRec("src/api/b.ts"),
		mkRec("src/lib/c.ts"),
	}
	batches := BatchRecords(recs, 5)
	total := 0
	for _, b := range batches {
		total += len(b)
	}
	require.Equal(t, 3, total)
	require.NotEmpty(t, batches)
}

func TestBatchRecordsSplitsOversizedDir(t *testing.T) {
	recs := []*core.FileRecord{}
	for i := 0; i < 7; i++ {
		recs = append(recs, mkRec("src/api/f"+intToStringT(i)+".ts"))
	}
	batches := BatchRecords(recs, 3)
	require.Equal(t, 3, len(batches))
	total := 0
	for _, b := range batches {
		require.LessOrEqual(t, len(b), 3)
		total += len(b)
	}
	require.Equal(t, 7, total)
}

func TestBatchRecordsEmptyInput(t *testing.T) {
	require.Empty(t, BatchRecords(nil, 5))
}

func intToStringT(n int) string {
	if n == 0 {
		return "0"
	}
	return string(rune('0' + n))
}
