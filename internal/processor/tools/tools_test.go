package tools

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReadFileRejectsEscapesAndSlicesLines(t *testing.T) {
	root := t.TempDir()
	write(t, root, "src/app.ts", "one\ntwo\nthree\n")
	ts := ByName(New(root))

	out, err := ts["read_file"].Run(context.Background(), raw(map[string]any{
		"path": "src/app.ts", "start_line": 2, "end_line": 3,
	}))
	require.NoError(t, err)
	require.Contains(t, out, "src/app.ts:2-3")
	require.Contains(t, out, "2  two")
	require.Contains(t, out, "3  three")

	_, err = ts["read_file"].Run(context.Background(), raw(map[string]any{"path": "../secret"}))
	require.Error(t, err)
}

func TestGrepHonorsGitignoreGlobAndCaps(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, exec.Command("git", "-C", root, "init").Run())
	write(t, root, ".gitignore", "ignored.ts\n")
	write(t, root, "src/a.ts", "safe\nsanitize(id)\n")
	write(t, root, "src/b.go", "sanitize(id)\n")
	write(t, root, "ignored.ts", "sanitize(secret)\n")
	ts := ByName(New(root))

	out, err := ts["grep"].Run(context.Background(), raw(map[string]any{
		"pattern": "sanitize", "glob": "**/*.ts", "max_results": 1,
	}))
	require.NoError(t, err)
	require.Contains(t, out, "src/a.ts:2")
	require.NotContains(t, out, "src/b.go")
	require.NotContains(t, out, "ignored.ts")
	require.Contains(t, out, "results truncated")
}

func TestFindCallersAndReadNeighbors(t *testing.T) {
	root := t.TempDir()
	write(t, root, "src/app.go", "package main\n\nfunc main() {\n\tvalidate(id)\n}\n")
	ts := ByName(New(root))

	callers, err := ts["find_callers"].Run(context.Background(), raw(map[string]any{"symbol": "validate"}))
	require.NoError(t, err)
	require.Contains(t, callers, "src/app.go:4")

	neighbors, err := ts["read_neighbors"].Run(context.Background(), raw(map[string]any{
		"path": "src/app.go", "line": 4, "radius": 1,
	}))
	require.NoError(t, err)
	require.Contains(t, neighbors, "3  func main()")
	require.Contains(t, neighbors, "4  \tvalidate(id)")
}

func TestGitBlameReturnsLineMetadata(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, exec.Command("git", "-C", root, "init").Run())
	require.NoError(t, exec.Command("git", "-C", root, "config", "user.email", "test@example.com").Run())
	require.NoError(t, exec.Command("git", "-C", root, "config", "user.name", "Test User").Run())
	require.NoError(t, exec.Command("git", "-C", root, "config", "commit.gpgsign", "false").Run())
	write(t, root, "src/app.ts", "const id = req.params.id\n")
	require.NoError(t, exec.Command("git", "-C", root, "add", ".").Run())
	require.NoError(t, exec.Command("git", "-C", root, "commit", "-m", "add app").Run())

	ts := ByName(New(root))
	out, err := ts["git_blame"].Run(context.Background(), raw(map[string]any{"path": "src/app.ts", "line": 1}))
	require.NoError(t, err)
	require.Contains(t, out, "src/app.ts:1 commit=")
	require.Contains(t, out, "author=Test User")
	require.Contains(t, out, "summary=add app")
}

func TestReadFileTruncatesLargeOutput(t *testing.T) {
	root := t.TempDir()
	write(t, root, "big.txt", strings.Repeat("abcdef\n", 4000))
	ts := ByName(New(root))
	out, err := ts["read_file"].Run(context.Background(), raw(map[string]any{"path": "big.txt"}))
	require.NoError(t, err)
	require.Contains(t, out, "results truncated")
	require.Contains(t, out, "source truncated at tool byte limit")
}

func TestReadBoundedFileNeverLoadsBeyondLimit(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "large.txt")
	require.NoError(t, os.WriteFile(path, []byte(strings.Repeat("x", MaxReadBytes*2)), 0o600))
	body, truncated, err := readBoundedFile(path, MaxReadBytes)
	require.NoError(t, err)
	require.True(t, truncated)
	require.Len(t, body, MaxReadBytes)
}

func TestReadFileRejectsSymlinkEscapeAndRedactsOutput(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.txt")
	require.NoError(t, os.WriteFile(outside, []byte("API_KEY=sk-test-abcdefghijklmnopqrstuvwxyz\n"), 0o600))
	require.NoError(t, os.Symlink(outside, filepath.Join(root, "escape.txt")))
	write(t, root, "src/config.ts", "const API_KEY = 'sk-test-abcdefghijklmnopqrstuvwxyz'\n")
	ts := ByName(New(root))

	_, err := ts["read_file"].Run(context.Background(), raw(map[string]any{"path": "escape.txt"}))
	require.Error(t, err)
	out, err := ts["read_file"].Run(context.Background(), raw(map[string]any{"path": "src/config.ts"}))
	require.NoError(t, err)
	require.NotContains(t, out, "sk-test-abcdefghijklmnopqrstuvwxyz")
	require.Contains(t, out, "[REDACTED]")
}

func write(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
	require.NoError(t, os.WriteFile(p, []byte(body), 0o644))
}

func raw(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}
