package bench

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// makeFakeRemote initializes a throwaway git repo with a single
// committed file and returns its path + the commit SHA. The remote is
// just a regular bare-ish working tree; `git fetch <path> <sha>` works
// against it the same way it would against a real URL.
func makeFakeRemote(t *testing.T) (path, sha string) {
	t.Helper()
	dir := t.TempDir()
	for _, args := range [][]string{
		{"init", "--quiet"},
		{"-c", "user.email=test@example.com", "-c", "user.name=Test", "-c", "commit.gpgsign=false",
			"commit", "--allow-empty", "--quiet", "-m", "seed"},
	} {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		out, err := cmd.CombinedOutput()
		require.NoErrorf(t, err, "git %v: %s", args, string(out))
	}
	// Add a real file so the scan has something to read.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "marker.txt"), []byte("hello fixture\n"), 0o600))
	for _, args := range [][]string{
		{"add", "marker.txt"},
		{"-c", "user.email=test@example.com", "-c", "user.name=Test", "-c", "commit.gpgsign=false",
			"commit", "--quiet", "-m", "add marker"},
	} {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		out, err := cmd.CombinedOutput()
		require.NoErrorf(t, err, "git %v: %s", args, string(out))
	}
	out, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output()
	require.NoError(t, err)
	return dir, strings.TrimSpace(string(out))
}

func TestMaterializeSourceVendoredFallback(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(dir, "source"), 0o700))
	got, cleanup, err := materializeSource(dir, TaskConfig{})
	require.NoError(t, err)
	defer cleanup()
	require.Equal(t, filepath.Join(dir, "source"), got)
}

func TestMaterializeSourceClonesAtPinnedSHA(t *testing.T) {
	remote, sha := makeFakeRemote(t)
	cfg := TaskConfig{Repo: &RepoSource{URL: remote, Commit: sha}}
	got, cleanup, err := materializeSource(t.TempDir(), cfg)
	require.NoError(t, err)
	defer cleanup()
	body, err := os.ReadFile(filepath.Join(got, "marker.txt"))
	require.NoError(t, err)
	require.Equal(t, "hello fixture\n", string(body))

	// Confirm the clone is at the exact SHA, not a branch tip that
	// could drift if the remote moves.
	out, err := exec.Command("git", "-C", got, "rev-parse", "HEAD").Output()
	require.NoError(t, err)
	require.Equal(t, sha, strings.TrimSpace(string(out)))
}

func TestMaterializeSourceCleanupRemovesClone(t *testing.T) {
	remote, sha := makeFakeRemote(t)
	cfg := TaskConfig{Repo: &RepoSource{URL: remote, Commit: sha}}
	got, cleanup, err := materializeSource(t.TempDir(), cfg)
	require.NoError(t, err)
	require.DirExists(t, got)
	cleanup()
	_, err = os.Stat(got)
	require.True(t, os.IsNotExist(err), "expected clone dir removed, got %v", err)
}

func TestMaterializeSourceRejectsBadSHA(t *testing.T) {
	remote, _ := makeFakeRemote(t)
	cfg := TaskConfig{Repo: &RepoSource{URL: remote, Commit: "0123456789abcdef0123456789abcdef01234567"}}
	_, cleanup, err := materializeSource(t.TempDir(), cfg)
	if cleanup != nil {
		defer cleanup()
	}
	require.Error(t, err)
	require.Contains(t, err.Error(), "fetch")
}

func TestLoadTaskConfigRejectsPartialRepo(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "task.toml")
	require.NoError(t, os.WriteFile(path, []byte("[repo]\nurl = \"https://example/x\"\n"), 0o600))
	_, err := loadTaskConfig(path)
	require.Error(t, err)
	require.Contains(t, err.Error(), "url and commit")
}
