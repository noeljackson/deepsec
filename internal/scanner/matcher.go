// Package scanner walks a project, detects tech tags, and runs the
// TOML matcher pack to produce CandidateMatch records.
package scanner

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/noeljackson/deepsec/internal/core"
	scannerast "github.com/noeljackson/deepsec/internal/scanner/ast"
)

// NoiseTier sorts matchers by precision: precise < normal < noisy.
type NoiseTier string

const (
	NoisePrecise NoiseTier = "precise"
	NoiseNormal  NoiseTier = "normal"
	NoiseNoisy   NoiseTier = "noisy"
)

func (t NoiseTier) Rank() int {
	switch t {
	case NoisePrecise:
		return 0
	case NoiseNoisy:
		return 2
	}
	return 1
}

// MatcherGate is the `requires = { ... }` block. Empty gate always
// runs; tech and sentinel_files are unioned (OR).
type MatcherGate struct {
	Tech             []string `toml:"tech,omitempty"`
	SentinelFiles    []string `toml:"sentinel_files,omitempty"`
	SentinelContains []string `toml:"sentinel_contains,omitempty"`
}

// MatcherDef is the declarative TOML record. Compile() turns it into a
// runnable Matcher.
type MatcherDef struct {
	Slug                string          `toml:"slug"`
	Description         string          `toml:"description"`
	NoiseTier           NoiseTier       `toml:"noise_tier,omitempty"`
	FilePatterns        []string        `toml:"file_patterns"`
	Patterns            []string        `toml:"patterns"`
	ASTPatterns         []ASTPatternDef `toml:"ast_patterns,omitempty"`
	SuppressPatterns    []string        `toml:"suppress_patterns,omitempty"`
	RequireContent      []string        `toml:"require_content,omitempty"`
	ExcludePathPatterns []string        `toml:"exclude_path_patterns,omitempty"`
	SnippetBefore       int             `toml:"snippet_before,omitempty"`
	SnippetAfter        int             `toml:"snippet_after,omitempty"`
	Label               string          `toml:"label,omitempty"`
	Requires            MatcherGate     `toml:"requires,omitempty"`
}

type ASTPatternDef struct {
	Language          string            `toml:"language"`
	Query             string            `toml:"query"`
	Label             string            `toml:"label,omitempty"`
	PrimaryCapture    string            `toml:"primary_capture,omitempty"`
	SnippetCapture    string            `toml:"snippet_capture,omitempty"`
	PrefilterPatterns []string          `toml:"prefilter_patterns,omitempty"`
	CaptureLabels     map[string]string `toml:"capture_labels,omitempty"`
}

// Matcher is a compiled matcher ready to run against source files.
type Matcher struct {
	Def           MatcherDef
	patterns      []*regexp.Regexp
	astPatterns   []compiledASTPattern
	suppress      []*regexp.Regexp
	require       []*regexp.Regexp
	excludePaths  []*regexp.Regexp
	snippetBefore int
	snippetAfter  int
}

type compiledASTPattern struct {
	def            ASTPatternDef
	language       scannerast.Language
	query          scannerast.Query
	prefilters     []*regexp.Regexp
	primaryCapture string
	snippetCapture string
	label          string
}

func (m *Matcher) Slug() string           { return m.Def.Slug }
func (m *Matcher) FilePatterns() []string { return m.Def.FilePatterns }
func (m *Matcher) Requires() MatcherGate  { return m.Def.Requires }
func (m *Matcher) NoiseTier() NoiseTier   { return m.Def.NoiseTier }
func (m *Matcher) Description() string    { return m.Def.Description }
func (m *Matcher) HasASTPatterns() bool   { return len(m.astPatterns) > 0 }

func (m *Matcher) ASTLanguages() []scannerast.Language {
	seen := map[scannerast.Language]struct{}{}
	var out []scannerast.Language
	for _, p := range m.astPatterns {
		if _, ok := seen[p.language]; ok {
			continue
		}
		seen[p.language] = struct{}{}
		out = append(out, p.language)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Match runs the matcher's patterns against `content` (already
// CRLF-normalized) and returns CandidateMatch hits. Suppress patterns
// inspect the snippet window and drop the hit if any match.
func (m *Matcher) Match(content, filePath string) []core.CandidateMatch {
	for _, ex := range m.excludePaths {
		if ex.MatchString(filePath) {
			return nil
		}
	}
	for _, req := range m.require {
		if !req.MatchString(content) {
			return nil
		}
	}
	lines := strings.Split(content, "\n")
	out := make([]core.CandidateMatch, 0)
	seen := map[string]bool{}
	for _, pat := range m.patterns {
		matches := pat.FindAllStringIndex(content, -1)
		for _, m2 := range matches {
			lineNum := 1 + strings.Count(content[:m2[0]], "\n")
			snippet := buildSnippet(lines, lineNum, m.snippetBefore, m.snippetAfter)
			if anyMatch(m.suppress, snippet) {
				continue
			}
			label := m.Def.Label
			if label == "" {
				label = pat.String()
			}
			key := fmt.Sprintf("%s|%s|%d", m.Def.Slug, label, lineNum)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, core.CandidateMatch{
				VulnSlug:       m.Def.Slug,
				LineNumbers:    []int{lineNum},
				Snippet:        snippet,
				MatchedPattern: label,
			})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].LineNumbers[0] != out[j].LineNumbers[0] {
			return out[i].LineNumbers[0] < out[j].LineNumbers[0]
		}
		return out[i].MatchedPattern < out[j].MatchedPattern
	})
	return out
}

func (m *Matcher) EligibleASTPatterns(content, filePath string, lang scannerast.Language) []compiledASTPattern {
	if len(m.astPatterns) == 0 {
		return nil
	}
	for _, ex := range m.excludePaths {
		if ex.MatchString(filePath) {
			return nil
		}
	}
	for _, req := range m.require {
		if !req.MatchString(content) {
			return nil
		}
	}
	var out []compiledASTPattern
	for _, p := range m.astPatterns {
		if p.language != lang {
			continue
		}
		if len(p.prefilters) > 0 && !anyMatch(p.prefilters, content) {
			continue
		}
		out = append(out, p)
	}
	return out
}

func (m *Matcher) MatchAST(tree scannerast.Tree, filePath string, patterns []compiledASTPattern) []core.CandidateMatch {
	// Tree-sitter query execution is deliberately not faked. Until grammar
	// WASM plus the parser ABI adapter are committed, AST patterns compile and
	// route correctly but do not emit candidates.
	return nil
}

func anyMatch(rs []*regexp.Regexp, s string) bool {
	for _, r := range rs {
		if r.MatchString(s) {
			return true
		}
	}
	return false
}

func buildSnippet(lines []string, lineNum, before, after int) string {
	start := lineNum - 1 - before
	if start < 0 {
		start = 0
	}
	end := lineNum + after
	if end > len(lines) {
		end = len(lines)
	}
	return strings.Join(lines[start:end], "\n")
}

// Compile turns a MatcherDef into a runnable Matcher. Returns an error
// if any pattern is an invalid Go regexp.
func Compile(d MatcherDef) (*Matcher, error) {
	if len(d.Patterns) == 0 && len(d.ASTPatterns) == 0 {
		return nil, fmt.Errorf("matcher %q: at least one of patterns or ast_patterns is required", d.Slug)
	}
	if d.SnippetBefore == 0 {
		d.SnippetBefore = 1
	}
	if d.SnippetAfter == 0 {
		d.SnippetAfter = 5
	}
	if d.NoiseTier == "" {
		d.NoiseTier = NoiseNormal
	}
	patterns, err := compileRegexes(d.Slug, d.Patterns)
	if err != nil {
		return nil, err
	}
	suppress, err := compileRegexes(d.Slug, d.SuppressPatterns)
	if err != nil {
		return nil, err
	}
	require, err := compileRegexes(d.Slug, d.RequireContent)
	if err != nil {
		return nil, err
	}
	excludePaths, err := compileRegexes(d.Slug, d.ExcludePathPatterns)
	if err != nil {
		return nil, err
	}
	astPatterns, err := compileASTPatterns(d)
	if err != nil {
		return nil, err
	}
	return &Matcher{
		Def:           d,
		patterns:      patterns,
		astPatterns:   astPatterns,
		suppress:      suppress,
		require:       require,
		excludePaths:  excludePaths,
		snippetBefore: d.SnippetBefore,
		snippetAfter:  d.SnippetAfter,
	}, nil
}

func compileASTPatterns(d MatcherDef) ([]compiledASTPattern, error) {
	out := make([]compiledASTPattern, 0, len(d.ASTPatterns))
	for i, p := range d.ASTPatterns {
		lang := scannerast.Language(p.Language)
		if !scannerast.IsSupported(lang) {
			return nil, fmt.Errorf("matcher %q ast_patterns[%d]: unsupported language %q", d.Slug, i, p.Language)
		}
		q, err := scannerast.ParseQuery(lang, p.Query)
		if err != nil {
			return nil, fmt.Errorf("matcher %q ast_patterns[%d]: %w", d.Slug, i, err)
		}
		primary := normalizeCaptureName(p.PrimaryCapture)
		if primary == "" {
			primary = "@match"
		}
		if !q.HasCapture(primary) {
			return nil, fmt.Errorf("matcher %q ast_patterns[%d]: primary_capture %q not found in query", d.Slug, i, primary)
		}
		snippet := normalizeCaptureName(p.SnippetCapture)
		if snippet == "" {
			snippet = primary
		}
		if !q.HasCapture(snippet) {
			return nil, fmt.Errorf("matcher %q ast_patterns[%d]: snippet_capture %q not found in query", d.Slug, i, snippet)
		}
		if len(p.CaptureLabels) > 0 {
			return nil, fmt.Errorf("matcher %q ast_patterns[%d]: capture_labels is reserved for a follow-up implementation", d.Slug, i)
		}
		prefilters, err := compileRegexes(d.Slug, p.PrefilterPatterns)
		if err != nil {
			return nil, fmt.Errorf("ast_patterns[%d] prefilter: %w", i, err)
		}
		label := p.Label
		if label == "" {
			label = d.Label
		}
		if label == "" {
			label = "ast:" + p.Language + ":" + strings.TrimPrefix(primary, "@")
		}
		out = append(out, compiledASTPattern{
			def:            p,
			language:       lang,
			query:          q,
			prefilters:     prefilters,
			primaryCapture: primary,
			snippetCapture: snippet,
			label:          label,
		})
	}
	return out, nil
}

func normalizeCaptureName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	if strings.HasPrefix(name, "@") {
		return name
	}
	return "@" + name
}

func compileRegexes(slug string, patterns []string) ([]*regexp.Regexp, error) {
	out := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		r, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("matcher %q: regex %q: %w", slug, p, err)
		}
		out = append(out, r)
	}
	return out, nil
}
