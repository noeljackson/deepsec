package core

import (
	"os"
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

func TestPersistenceUsesPrivateModesAndRejectsSymlinks(t *testing.T) {
	r := tempRoot(t)
	_, err := r.EnsureProject("p", "/tmp/x", "")
	require.NoError(t, err)

	dataInfo, err := os.Stat(r.Path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o700), dataInfo.Mode().Perm())
	projectDir, err := r.DataDir("p")
	require.NoError(t, err)
	projectInfo, err := os.Stat(projectDir)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o700), projectInfo.Mode().Perm())

	rec := &FileRecord{FilePath: "src/a.ts", ProjectID: "p", Status: StatusPending}
	require.NoError(t, r.WriteFileRecord(rec))
	path, err := r.FileRecordPath("p", "src/a.ts")
	require.NoError(t, err)
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	link, err := r.FileRecordPath("p", "src/linked.ts")
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Dir(link), 0o700))
	require.NoError(t, os.Symlink(path, link))
	_, err = r.ReadFileRecord("p", "src/linked.ts")
	require.Error(t, err)
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

func TestReadFileRecordRedactsLegacySensitiveFields(t *testing.T) {
	r := tempRoot(t)
	_, err := r.EnsureProject("p", "/tmp/x", "")
	require.NoError(t, err)
	rec := &FileRecord{
		FilePath: "src/a.ts", ProjectID: "p", Status: StatusPending,
		Candidates: []CandidateMatch{{VulnSlug: "test", Snippet: "api_key=sk-test-abcdefghijklmnopqrstuvwxyz"}},
	}
	require.NoError(t, r.WriteFileRecord(rec))
	path, err := r.FileRecordPath("p", "src/a.ts")
	require.NoError(t, err)
	// Simulate a pre-redaction Deepsec record retained on disk.
	require.NoError(t, os.WriteFile(path, []byte(`{"filePath":"src/a.ts","projectId":"p","candidates":[{"vulnSlug":"test","snippet":"api_key=sk-test-abcdefghijklmnopqrstuvwxyz"}],"status":"pending"}`), 0o600))
	got, err := r.ReadFileRecord("p", "src/a.ts")
	require.NoError(t, err)
	require.NotContains(t, got.Candidates[0].Snippet, "sk-test-abcdefghijklmnopqrstuvwxyz")
	require.Contains(t, got.Candidates[0].Snippet, RedactedSecret)
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

func TestReadRunMetaRejectsSymlink(t *testing.T) {
	r := tempRoot(t)
	_, err := r.EnsureProject("p", "/tmp/x", "")
	require.NoError(t, err)
	m := NewRunMeta("p", "20260511000000-aaaa", "/tmp/x", RunTypeScan)
	require.NoError(t, r.WriteRunMeta(m))
	p, err := r.RunMetaPath("p", m.RunID)
	require.NoError(t, err)
	target := filepath.Join(t.TempDir(), "run.json")
	require.NoError(t, os.WriteFile(target, []byte("{}"), 0o600))
	require.NoError(t, os.Remove(p))
	require.NoError(t, os.Symlink(target, p))
	_, err = r.ReadRunMeta("p", m.RunID)
	require.Error(t, err)
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
	for i := 0; i < 1000; i++ {
		id := GenerateRunID()
		require.Len(t, id, 14+1+8)
		require.Equal(t, byte('-'), id[14])
		require.False(t, seen[id], "duplicate run id: %s", id)
		seen[id] = true
	}
}

func TestFileHashHexStable(t *testing.T) {
	require.Equal(t, FileHashHex([]byte("hi")), FileHashHex([]byte("hi")))
	require.NotEqual(t, FileHashHex([]byte("hi")), FileHashHex([]byte("ho")))
}
