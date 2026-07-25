package scanner

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
)

func writeFile(t *testing.T, dir, rel, body string) {
	t.Helper()
	p := filepath.Join(dir, rel)
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
	require.NoError(t, os.WriteFile(p, []byte(body), 0o644))
}

func TestWalkerPicksUpSourceFiles(t *testing.T) {
	d := t.TempDir()
	writeFile(t, d, "src/a.ts", "export const x = 1;")
	writeFile(t, d, "src/b.py", "x = 1")
	writeFile(t, d, "src/c.go", "package main")
	files, err := WalkProject(d)
	require.NoError(t, err)
	require.Contains(t, files, "src/a.ts")
	require.Contains(t, files, "src/b.py")
	require.Contains(t, files, "src/c.go")
}

func TestWalkerSkipsIgnoredDirs(t *testing.T) {
	d := t.TempDir()
	writeFile(t, d, "src/a.ts", "x")
	writeFile(t, d, "node_modules/foo/index.js", "x")
	writeFile(t, d, ".git/HEAD", "ref")
	writeFile(t, d, "target/foo.rs", "x")
	writeFile(t, d, "dist/bundle.js", "x")
	files, err := WalkProject(d)
	require.NoError(t, err)
	require.Contains(t, files, "src/a.ts")
	require.False(t, slices.ContainsFunc(files, func(s string) bool {
		return containsAnySub(s, []string{"node_modules", ".git", "target/", "dist/"})
	}))
}

func TestWalkerSkipsBinaryExtensions(t *testing.T) {
	d := t.TempDir()
	writeFile(t, d, "src/a.ts", "x")
	writeFile(t, d, "img/logo.png", "binary")
	writeFile(t, d, "doc/readme.md", "# hi")
	files, err := WalkProject(d)
	require.NoError(t, err)
	require.Contains(t, files, "src/a.ts")
	for _, f := range files {
		require.NotContains(t, f, ".png")
		require.NotContains(t, f, ".md")
	}
}

func TestWalkerHonorsGitignore(t *testing.T) {
	d := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(d, ".git"), 0o755))
	writeFile(t, d, ".gitignore", "secret.ts\n")
	writeFile(t, d, "src/a.ts", "x")
	writeFile(t, d, "secret.ts", "API_KEY=...")
	files, err := WalkProject(d)
	require.NoError(t, err)
	require.Contains(t, files, "src/a.ts")
	require.NotContains(t, files, "secret.ts")
}

func TestWalkerSkipsSymlinks(t *testing.T) {
	d := t.TempDir()
	writeFile(t, d, "src/real.ts", "export const safe = true")
	require.NoError(t, os.Symlink(filepath.Join(d, "src", "real.ts"), filepath.Join(d, "src", "linked.ts")))
	files, err := WalkProject(d)
	require.NoError(t, err)
	require.Contains(t, files, "src/real.ts")
	require.NotContains(t, files, "src/linked.ts")
}

func TestIgnoreDirsContainsExpected(t *testing.T) {
	for _, name := range []string{"node_modules", ".git", "target", "dist"} {
		_, ok := IgnoreDirs[name]
		require.True(t, ok, "%s missing", name)
	}
}

func containsAnySub(s string, subs []string) bool {
	for _, sub := range subs {
		if len(sub) <= len(s) {
			for i := 0; i+len(sub) <= len(s); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}
