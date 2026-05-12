package bench

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/noeljackson/deepsec/internal/scanner"
)

type LintSeverity string

const (
	LintError   LintSeverity = "error"
	LintWarning LintSeverity = "warning"
)

type LintFinding struct {
	Severity LintSeverity `json:"severity"`
	File     string       `json:"file"`
	Line     int          `json:"line"`
	Slug     string       `json:"slug,omitempty"`
	Check    string       `json:"check"`
	Message  string       `json:"message"`
}

func (f LintFinding) TSV() string {
	return fmt.Sprintf("%s\t%s\t%d\t%s\t%s\t%s", f.Severity, f.File, f.Line, f.Slug, f.Check, strings.ReplaceAll(f.Message, "\t", " "))
}

func LintMatchers(dir string) ([]LintFinding, error) {
	if dir == "" {
		dir = filepath.Join("internal", "scanner", "matchers")
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.toml"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	var findings []LintFinding
	seen := map[string]string{}
	for _, file := range files {
		body, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		var mf scanner.MatcherFile
		if _, err := toml.Decode(string(body), &mf); err != nil {
			findings = append(findings, LintFinding{Severity: LintError, File: file, Line: 1, Check: "toml", Message: err.Error()})
			continue
		}
		lines := strings.Split(string(body), "\n")
		for _, m := range mf.Matchers {
			line := lineOfSlug(lines, m.Slug)
			if prev, ok := seen[m.Slug]; ok {
				findings = append(findings, LintFinding{Severity: LintError, File: file, Line: line, Slug: m.Slug, Check: "duplicate-slug", Message: "duplicate vulnSlug previously declared in " + prev})
			} else {
				seen[m.Slug] = fmt.Sprintf("%s:%d", file, line)
			}
			findings = append(findings, lintRegexGroup(file, lines, m.Slug, "patterns", m.Patterns)...)
			findings = append(findings, lintRegexGroup(file, lines, m.Slug, "suppress_patterns", m.SuppressPatterns)...)
			findings = append(findings, lintRegexGroup(file, lines, m.Slug, "require_content", m.RequireContent)...)
			findings = append(findings, lintRegexGroup(file, lines, m.Slug, "exclude_path_patterns", m.ExcludePathPatterns)...)
			if m.NoiseTier == scanner.NoiseNoisy && !hasGate(m) {
				findings = append(findings, LintFinding{Severity: LintWarning, File: file, Line: line, Slug: m.Slug, Check: "noisy-without-gate", Message: `noise_tier="noisy" matcher has no requires.* or require_content gate`})
			}
			if overbroadFilePatterns(m.FilePatterns) && !hasGate(m) {
				findings = append(findings, LintFinding{Severity: LintWarning, File: file, Line: line, Slug: m.Slug, Check: "overbroad-file-patterns", Message: "empty or **/* file_patterns without another gate"})
			}
		}
	}
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		return findings[i].Line < findings[j].Line
	})
	return findings, nil
}

func HasLintErrors(findings []LintFinding) bool {
	for _, f := range findings {
		if f.Severity == LintError {
			return true
		}
	}
	return false
}

func lintRegexGroup(file string, lines []string, slug, check string, patterns []string) []LintFinding {
	var out []LintFinding
	for _, pat := range patterns {
		line := lineOfValue(lines, pat)
		if reason := unsupportedRE2Syntax(pat); reason != "" {
			out = append(out, LintFinding{Severity: LintError, File: file, Line: line, Slug: slug, Check: check + "-unsupported-regex", Message: reason})
			continue
		}
		if _, err := regexp.Compile(pat); err != nil {
			out = append(out, LintFinding{Severity: LintError, File: file, Line: line, Slug: slug, Check: check + "-invalid-regex", Message: err.Error()})
		}
	}
	return out
}

func unsupportedRE2Syntax(pat string) string {
	for _, token := range []string{"(?=", "(?!", "(?<=", "(?<!"} {
		if strings.Contains(pat, token) {
			return "unsupported RE2 syntax: lookaround " + token
		}
	}
	if regexp.MustCompile(`\\[1-9]`).FindString(pat) != "" {
		return "unsupported RE2 syntax: backreference"
	}
	return ""
}

func hasGate(m scanner.MatcherDef) bool {
	return len(m.RequireContent) > 0 || len(m.Requires.Tech) > 0 || len(m.Requires.SentinelFiles) > 0 || len(m.Requires.SentinelContains) > 0
}

func overbroadFilePatterns(patterns []string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, p := range patterns {
		if p == "**/*" || p == "*" {
			return true
		}
	}
	return false
}

func lineOfSlug(lines []string, slug string) int {
	needle := `slug = "` + slug + `"`
	for i, line := range lines {
		if strings.Contains(line, needle) {
			return i + 1
		}
	}
	return 1
}

func lineOfValue(lines []string, value string) int {
	plain := strings.ReplaceAll(value, `\`, `\\`)
	for i, line := range lines {
		if strings.Contains(line, value) || strings.Contains(line, plain) {
			return i + 1
		}
	}
	return 1
}
