package core

import (
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
)

func tempRoot(t *testing.T) DataRoot {
	t.Helper()
	return DataRootFromPath(filepath.Join(t.TempDir(), "data"))
}

func TestEnsureProjectIsIdempotent(t *testing.T) {
	r := tempRoot(t)
	a, err := r.EnsureProject("p", "/tmp/x", "https://github.com/x/r")
	require.NoError(t, err)
	b, err := r.EnsureProject("p", "/tmp/x", "")
	require.NoError(t, err)
	require.Equal(t, a.ProjectID, b.ProjectID)
	require.Equal(t, a.CreatedAt, b.CreatedAt)
	require.Equal(t, "https://github.com/x/r", a.GithubURL)
}

func TestReadProjectConfigMissingReturnsNil(t *testing.T) {
	r := tempRoot(t)
	cfg, err := r.ReadProjectConfig("missing")
	require.NoError(t, err)
	require.Nil(t, cfg)
}

func TestFileRecordRoundtrip(t *testing.T) {
	r := tempRoot(t)
	_, err := r.EnsureProject("p", "/tmp/x", "")
	require.NoError(t, err)
	rec := &FileRecord{
		FilePath:         "src/a.ts",
		ProjectID:        "p",
		Candidates:       []CandidateMatch{{VulnSlug: "s", LineNumbers: []int{1}, Snippet: "x", MatchedPattern: "p"}},
		LastScannedAt:    "2026-05-11T00:00:00Z",
		LastScannedRunID: "r",
		FileHash:         "h",
		Status:           StatusPending,
	}
	require.NoError(t, r.WriteFileRecord(rec))
	back, err := r.ReadFileRecord("p", "src/a.ts")
	require.NoError(t, err)
	require.NotNil(t, back)
	require.Equal(t, "src/a.ts", back.FilePath)
	require.Len(t, back.Candidates, 1)
}

func TestReadFileRecordMissingReturnsNil(t *testing.T) {
	r := tempRoot(t)
	_, err := r.EnsureProject("p", "/tmp/x", "")
	require.NoError(t, err)
	rec, err := r.ReadFileRecord("p", "nope.ts")
	require.NoError(t, err)
	require.Nil(t, rec)
}

func TestLoadAllFileRecordsWalksNestedDirs(t *testing.T) {
	r := tempRoot(t)
	_, err := r.EnsureProject("p", "/tmp/x", "")
	require.NoError(t, err)
	for _, path := range []string{"a.ts", "src/b.ts", "src/lib/c.ts"} {
		rec := &FileRecord{
			FilePath:         path,
			ProjectID:        "p",
			LastScannedAt:    "2026-05-11T00:00:00Z",
			LastScannedRunID: "r",
			FileHash:         "h",
			Status:           StatusPending,
		}
		require.NoError(t, r.WriteFileRecord(rec))
	}
	all, err := r.LoadAllFileRecords("p")
	require.NoError(t, err)
	paths := make([]string, len(all))
	for i, x := range all {
		paths[i] = x.FilePath
	}
	sort.Strings(paths)
	require.Equal(t, []string{"a.ts", "src/b.ts", "src/lib/c.ts"}, paths)
}

func TestLoadAllFileRecordsEmptyProjectReturnsEmpty(t *testing.T) {
	r := tempRoot(t)
	_, err := r.EnsureProject("p", "/tmp/x", "")
	require.NoError(t, err)
	all, err := r.LoadAllFileRecords("p")
	require.NoError(t, err)
	require.Empty(t, all)
}

func TestRunMetaLifecycle(t *testing.T) {
	r := tempRoot(t)
	_, err := r.EnsureProject("p", "/tmp/x", "")
	require.NoError(t, err)
	m := NewRunMeta("p", "20260511000000-aaaa", "/tmp/x", RunTypeScan)
	require.Equal(t, RunPhaseRunning, m.Phase)
	require.NoError(t, r.WriteRunMeta(m))
	_, err = r.CompleteRun("p", "20260511000000-aaaa", RunPhaseDone)
	require.NoError(t, err)
	runs, err := r.ListRuns("p")
	require.NoError(t, err)
	require.Len(t, runs, 1)
	require.Equal(t, RunPhaseDone, runs[0].Phase)
	require.NotEmpty(t, runs[0].CompletedAt)
}

func TestCompleteRunMissingReturnsNil(t *testing.T) {
	r := tempRoot(t)
	_, err := r.EnsureProject("p", "/tmp/x", "")
	require.NoError(t, err)
	out, err := r.CompleteRun("p", "20260101000000-zzzz", RunPhaseDone)
	require.NoError(t, err)
	require.Nil(t, out)
}

func TestListRunsSortsNewestFirst(t *testing.T) {
	r := tempRoot(t)
	_, err := r.EnsureProject("p", "/tmp/x", "")
	require.NoError(t, err)
	for _, id := range []string{"20260101000000-aaaa", "20260601000000-bbbb", "20260301000000-cccc"} {
		m := NewRunMeta("p", id, "/tmp/x", RunTypeScan)
		require.NoError(t, r.WriteRunMeta(m))
	}
	runs, err := r.ListRuns("p")
	require.NoError(t, err)
	ids := make([]string, len(runs))
	for i, r := range runs {
		ids[i] = r.RunID
	}
	require.Equal(t, []string{
		"20260601000000-bbbb",
		"20260301000000-cccc",
		"20260101000000-aaaa",
	}, ids)
}

func TestRunIDGenerationUniqueAndWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		id := GenerateRunID()
		require.Len(t, id, 14+1+4)
		require.Equal(t, byte('-'), id[14])
		require.False(t, seen[id])
		seen[id] = true
	}
}

func TestFileHashHexStable(t *testing.T) {
	require.Equal(t, FileHashHex([]byte("hi")), FileHashHex([]byte("hi")))
	require.NotEqual(t, FileHashHex([]byte("hi")), FileHashHex([]byte("ho")))
}
