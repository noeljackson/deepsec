package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
)

// FileSourceArgs are the mutually-exclusive direct-mode flags.
type FileSourceArgs struct {
	Files     []string
	FilesFrom string
	Diff      string
}

// ResolvedFiles is what a non-empty FileSourceArgs evaluates to.
type ResolvedFiles struct {
	Files  []string
	Source string
}

// ResolveFiles validates the args and computes the bounded file list.
// Returns (nil, nil) when no direct-mode flag is set.
func ResolveFiles(args FileSourceArgs, repoRoot string) (*ResolvedFiles, error) {
	set := 0
	if len(args.Files) > 0 {
		set++
	}
	if args.FilesFrom != "" {
		set++
	}
	if args.Diff != "" {
		set++
	}
	if set == 0 {
		return nil, nil
	}
	if set > 1 {
		return nil, errors.New("--files / --files-from / --diff are mutually exclusive")
	}
	if len(args.Files) > 0 {
		return &ResolvedFiles{Files: clean(args.Files), Source: "files:cli"}, nil
	}
	if args.FilesFrom != "" {
		lines, err := readFilesFrom(args.FilesFrom)
		if err != nil {
			return nil, err
		}
		src := "files-from:" + args.FilesFrom
		return &ResolvedFiles{Files: clean(lines), Source: src}, nil
	}
	files, err := gitDiffFiles(repoRoot, args.Diff)
	if err != nil {
		return nil, err
	}
	return &ResolvedFiles{Files: files, Source: "git-diff:" + args.Diff}, nil
}

func clean(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range in {
		s = strings.ReplaceAll(strings.TrimSpace(s), `\`, `/`)
		if s == "" {
			continue
		}
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func readFilesFrom(path string) ([]string, error) {
	var r io.Reader
	if path == "-" {
		r = os.Stdin
	} else {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}
	var out []string
	s := bufio.NewScanner(r)
	for s.Scan() {
		out = append(out, s.Text())
	}
	return out, s.Err()
}

func gitDiffFiles(repoRoot, spec string) ([]string, error) {
	cmd := exec.Command("git", "-C", repoRoot, "diff", "--name-only", "--diff-filter=ACMR", spec)
	body, err := cmd.Output()
	if err != nil {
		stderr := ""
		if exitErr, ok := err.(*exec.ExitError); ok {
			stderr = string(exitErr.Stderr)
		}
		return nil, fmt.Errorf("git diff %s: %s%w", spec, stderr, err)
	}
	return clean(strings.Split(string(body), "\n")), nil
}
