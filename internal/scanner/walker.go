package scanner

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// IgnoreDirs are directory names always skipped during the walk.
var IgnoreDirs = map[string]struct{}{
	"node_modules":  {},
	".git":          {},
	".hg":           {},
	".svn":          {},
	"dist":          {},
	"build":         {},
	"out":           {},
	".next":         {},
	".nuxt":         {},
	".turbo":        {},
	".cache":        {},
	"coverage":      {},
	"__pycache__":   {},
	".pytest_cache": {},
	".mypy_cache":   {},
	"target":        {},
	"vendor":        {},
	".terraform":    {},
	".venv":         {},
	"venv":          {},
	".tox":          {},
	"deps":          {},
	"Pods":          {},
	".idea":         {},
	".vscode":       {},
}

// skipExtensions are extensions of files that source-level analysis
// gains nothing from (markdown, binaries, generated bundles).
var skipExtensions = map[string]struct{}{
	".md":     {},
	".lock":   {},
	".log":    {},
	".map":    {},
	".ico":    {},
	".png":    {},
	".jpg":    {},
	".jpeg":   {},
	".gif":    {},
	".webp":   {},
	".svg":    {},
	".pdf":    {},
	".zip":    {},
	".tar":    {},
	".gz":     {},
	".exe":    {},
	".dll":    {},
	".so":     {},
	".dylib":  {},
	".woff":   {},
	".woff2":  {},
	".ttf":    {},
	".min.js": {},
}

const maxFileSize = 1 << 20 // 1 MiB

// WalkProject returns the project-relative paths of every file under
// `root` that's a candidate for matching. Skips IgnoreDirs subtrees,
// skipExtensions, files over 1 MiB, and honors .gitignore.
func WalkProject(root string) ([]string, error) {
	ignorer := loadGitignore(root)
	out := make([]string, 0)
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if path == root {
			return nil
		}
		name := d.Name()
		if d.IsDir() {
			if _, drop := IgnoreDirs[name]; drop {
				return fs.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if ignorer != nil && ignorer.MatchesPath(rel) {
			return nil
		}
		if _, drop := skipExtensions[strings.ToLower(filepath.Ext(name))]; drop {
			return nil
		}
		// also drop the .min.js suffix specifically (Ext only catches `.js`)
		if strings.HasSuffix(strings.ToLower(name), ".min.js") {
			return nil
		}
		fi, err := os.Stat(path)
		if err != nil || fi.Size() > maxFileSize {
			return nil
		}
		out = append(out, rel)
		return nil
	})
	return out, err
}
