package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/noeljackson/deepsec/internal/core"
	"github.com/stretchr/testify/require"
)

// scaffoldScanProject builds a minimal on-disk project, runs Scan once
// to populate the cache, and returns the scanner Options.
func scaffoldScanProject(t *testing.T, source string) (Options, string) {
	t.Helper()
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "main.go"), []byte(source), 0o644))
	dr := core.DataRootFromPath(t.TempDir())
	opts := Options{
		ProjectID: "test-project",
		Root:      root,
		DataRoot:  dr,
	}
	return opts, root
}

func TestScanCacheHitOnUnchangedFile(t *testing.T) {
	src := `package main

import "os/exec"

func main() {
	exec.Command("sh", "-c", "id "+userInput)
}

var userInput string
`
	opts, _ := scaffoldScanProject(t, src)
	first, err := Scan(opts)
	require.NoError(t, err)
	require.GreaterOrEqual(t, first.FilesScanned, 1)
	require.Equal(t, 0, first.CacheHits, "first scan cannot be a cache hit")

	// Second scan with no file changes and no matcher pack changes.
	second, err := Scan(opts)
	require.NoError(t, err)
	require.Equal(t, second.FilesScanned, first.FilesScanned)
	require.GreaterOrEqual(t, second.CacheHits, 1, "expected at least one cache hit on rerun")
	require.Equal(t, second.CandidateCount, first.CandidateCount,
		"candidate count should be preserved across cache hits")
}

func TestScanCacheMissAfterFileChange(t *testing.T) {
	src := `package main

func main() { println("hello") }
`
	opts, root := scaffoldScanProject(t, src)
	_, err := Scan(opts)
	require.NoError(t, err)

	// Mutate the file → hash changes → cache miss.
	require.NoError(t, os.WriteFile(filepath.Join(root, "main.go"),
		[]byte(src+"// touched\n"), 0o644))
	second, err := Scan(opts)
	require.NoError(t, err)
	require.Equal(t, 0, second.CacheHits, "modified file should be re-scanned, not cached")
}

func TestScanForceRescanBypassesCache(t *testing.T) {
	src := `package main
func main() {}
`
	opts, _ := scaffoldScanProject(t, src)
	_, err := Scan(opts)
	require.NoError(t, err)

	opts.ForceRescan = true
	out, err := Scan(opts)
	require.NoError(t, err)
	require.Equal(t, 0, out.CacheHits, "--force-rescan should bypass the cache entirely")
}

func TestScanCacheMissAfterMatcherPackChange(t *testing.T) {
	src := `package main
import "fmt"
func main() { fmt.Println("hi") }
`
	opts, _ := scaffoldScanProject(t, src)
	_, err := Scan(opts)
	require.NoError(t, err)

	// Inject an extra matcher → pack hash changes → cache miss.
	extraDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(extraDir, "extra.toml"), []byte(`
[[matcher]]
slug = "test-cache-invalidator"
description = "test"
noise_tier = "normal"
file_patterns = ["**/*.go"]
patterns = ["never-matches-anything"]
label = "stub"
`), 0o644))
	opts.ExtraMatcherPaths = []string{extraDir}
	second, err := Scan(opts)
	require.NoError(t, err)
	require.Equal(t, 0, second.CacheHits,
		"adding a matcher should invalidate the cache, got %d hits", second.CacheHits)
}

func TestRegistryPackHashIsDeterministic(t *testing.T) {
	r1, err := WithBuiltin()
	require.NoError(t, err)
	r2, err := WithBuiltin()
	require.NoError(t, err)
	require.Equal(t, r1.PackHash(), r2.PackHash())

	// Mutate one and confirm hash diverges.
	r3, err := WithBuiltin()
	require.NoError(t, err)
	require.NoError(t, r3.LoadTOMLBytes([]byte(`
[[matcher]]
slug = "delta-matcher"
description = "test"
noise_tier = "normal"
file_patterns = ["**/*.x"]
patterns = ["x"]
label = "x"
`), "delta.toml"))
	require.NotEqual(t, r1.PackHash(), r3.PackHash())
}
