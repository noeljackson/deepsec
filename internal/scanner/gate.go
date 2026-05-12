package scanner

import (
	"os"
	"path/filepath"
	"regexp"

	"github.com/bmatcuk/doublestar/v4"
)

// EvaluateGate returns true when the matcher should run against the
// detected tech / root combo. Semantics: empty gate always runs; tech
// and sentinel_files are OR'd (union), not AND'd.
func EvaluateGate(g MatcherGate, tech DetectedTech, root string) bool {
	if len(g.Tech) == 0 && len(g.SentinelFiles) == 0 {
		return true
	}
	if len(g.Tech) > 0 {
		have := map[string]struct{}{}
		for _, t := range tech.Tags {
			have[t] = struct{}{}
		}
		for _, t := range g.Tech {
			if _, ok := have[t]; ok {
				return true
			}
		}
	}
	if len(g.SentinelFiles) > 0 && hasSentinel(g.SentinelFiles, g.SentinelContains, root) {
		return true
	}
	return false
}

func hasSentinel(patterns, contains []string, root string) bool {
	for _, p := range patterns {
		// Literal path? fast-path.
		if !containsAny(p, "*?[") {
			abs := filepath.Join(root, p)
			if _, err := os.Stat(abs); err != nil {
				continue
			}
			if len(contains) == 0 {
				return true
			}
			body, err := os.ReadFile(abs)
			if err == nil && matchesAny(string(body), contains) {
				return true
			}
			continue
		}
		// Glob path.
		match, err := globFind(root, p)
		if err != nil || match == "" {
			continue
		}
		if len(contains) == 0 {
			return true
		}
		body, err := os.ReadFile(match)
		if err == nil && matchesAny(string(body), contains) {
			return true
		}
	}
	return false
}

func globFind(root, pattern string) (string, error) {
	abs, err := doublestar.Glob(os.DirFS(root), pattern)
	if err != nil || len(abs) == 0 {
		return "", err
	}
	return filepath.Join(root, abs[0]), nil
}

func containsAny(s, chars string) bool {
	for _, c := range chars {
		for _, r := range s {
			if r == c {
				return true
			}
		}
	}
	return false
}

func matchesAny(body string, patterns []string) bool {
	for _, p := range patterns {
		r, err := regexp.Compile(p)
		if err != nil {
			continue
		}
		if r.MatchString(body) {
			return true
		}
	}
	return false
}
