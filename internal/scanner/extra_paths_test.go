package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

const customMatcherTOML = `
[[matcher]]
slug = "custom-test-marker"
description = "Synthetic test marker"
file_patterns = ["**/*.txt"]
patterns = ["TRIPWIRE-XYZ"]
noise_tier = "precise"
`

func TestLoadRegistryAcceptsExtraFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "custom.toml")
	require.NoError(t, os.WriteFile(path, []byte(customMatcherTOML), 0o600))

	reg, err := loadRegistry(Options{ExtraMatcherPaths: []string{path}})
	require.NoError(t, err)
	require.NotNil(t, reg.Get("custom-test-marker"), "custom matcher not registered")
}

func TestLoadRegistryAcceptsExtraDirectory(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "custom.toml"), []byte(customMatcherTOML), 0o600))

	reg, err := loadRegistry(Options{ExtraMatcherPaths: []string{dir}})
	require.NoError(t, err)
	require.NotNil(t, reg.Get("custom-test-marker"))
}

func TestLoadRegistryReportsMissingExtraPath(t *testing.T) {
	_, err := loadRegistry(Options{ExtraMatcherPaths: []string{"/no/such/dir/custom.toml"}})
	require.Error(t, err)
	require.Contains(t, err.Error(), "extra_paths")
}

func TestLoadRegistryExtraMatcherOverridesBundled(t *testing.T) {
	dir := t.TempDir()
	override := `
[[matcher]]
slug = "ssrf"
description = "Override SSRF"
file_patterns = ["**/*.zzz"]
patterns = ["OVERRIDDEN-MARKER"]
noise_tier = "precise"
`
	path := filepath.Join(dir, "override.toml")
	require.NoError(t, os.WriteFile(path, []byte(override), 0o600))

	reg, err := loadRegistry(Options{ExtraMatcherPaths: []string{path}})
	require.NoError(t, err)
	m := reg.Get("ssrf")
	require.NotNil(t, m)
	require.Equal(t, "Override SSRF", m.Description(), "extra path did not override bundled slug")
}
