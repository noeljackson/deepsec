package scanner

import (
	"os"
	"path/filepath"

	gitignore "github.com/sabhiram/go-gitignore"
)

// loadGitignore returns a parsed .gitignore matcher for `root`, or nil
// if either the file is missing or `root` is not inside a git repo.
// Mirrors the Rust port's behavior of honoring .gitignore only when
// a .git directory marks the repository.
func loadGitignore(root string) *gitignore.GitIgnore {
	if _, err := os.Stat(filepath.Join(root, ".git")); err != nil {
		return nil
	}
	p := filepath.Join(root, ".gitignore")
	if _, err := os.Stat(p); err != nil {
		return nil
	}
	gi, err := gitignore.CompileIgnoreFile(p)
	if err != nil {
		return nil
	}
	return gi
}
