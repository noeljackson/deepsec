package commands

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWritePrivateFileUsesPrivateModesAndRejectsSymlink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reports", "finding.json")
	require.NoError(t, writePrivateFile(path, []byte("redacted")))
	file, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), file.Mode().Perm())
	dir, err := os.Stat(filepath.Dir(path))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o700), dir.Mode().Perm())

	target := filepath.Join(t.TempDir(), "target")
	require.NoError(t, os.WriteFile(target, []byte("keep"), 0o600))
	require.NoError(t, os.Remove(path))
	require.NoError(t, os.Symlink(target, path))
	require.Error(t, writePrivateFile(path, []byte("overwrite")))
}
