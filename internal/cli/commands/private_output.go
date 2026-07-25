package commands

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// ensurePrivateDir and writePrivateFile are used for rendered scan material.
// Findings are redacted before they reach these writers, but their paths,
// descriptions, and security posture are still sensitive operational data.
func ensurePrivateDir(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	return os.Chmod(path, 0o700)
}

func writePrivateFile(path string, body []byte) error {
	if err := ensurePrivateDir(filepath.Dir(path)); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil && info.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("refusing to overwrite symlinked output: %s", path)
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(body); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}
