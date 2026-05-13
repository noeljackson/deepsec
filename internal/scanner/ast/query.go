package ast

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var (
	captureNameRE = regexp.MustCompile(`@[A-Za-z_][A-Za-z0-9_]*`)
	predicateRE   = regexp.MustCompile(`#([A-Za-z-]+\?)`)
)

var supportedPredicates = map[string]struct{}{
	"eq?":        {},
	"match?":     {},
	"not-eq?":    {},
	"not-match?": {},
}

type Query struct {
	Language       Language
	Source         string
	Captures       []string
	Predicates     []string
	TextPredicates []TextPredicate
}

type TextPredicate struct {
	Op      string
	Capture string
	Value   string
}

func ParseQuery(lang Language, source string) (Query, error) {
	if !IsSupported(lang) {
		return Query{}, fmt.Errorf("unsupported AST language %q", lang)
	}
	if strings.TrimSpace(source) == "" {
		return Query{}, fmt.Errorf("empty AST query")
	}
	if err := validateBalancedParens(source); err != nil {
		return Query{}, err
	}
	captures := uniqueStrings(captureNameRE.FindAllString(source, -1))
	if len(captures) == 0 {
		return Query{}, fmt.Errorf("AST query must define at least one capture")
	}
	var predicates []string
	for _, m := range predicateRE.FindAllStringSubmatch(source, -1) {
		name := m[1]
		if _, ok := supportedPredicates[name]; !ok {
			return Query{}, fmt.Errorf("unsupported AST query predicate #%s", name)
		}
		predicates = append(predicates, name)
	}
	predicates = uniqueStrings(predicates)
	textPredicates, err := parseTextPredicates(source)
	if err != nil {
		return Query{}, err
	}
	return Query{
		Language:       lang,
		Source:         source,
		Captures:       captures,
		Predicates:     predicates,
		TextPredicates: textPredicates,
	}, nil
}

func (q Query) HasCapture(name string) bool {
	if name == "" {
		return false
	}
	if !strings.HasPrefix(name, "@") {
		name = "@" + name
	}
	for _, c := range q.Captures {
		if c == name {
			return true
		}
	}
	return false
}

func validateBalancedParens(s string) error {
	depth := 0
	inString := false
	escaped := false
	for _, r := range s {
		if inString {
			if escaped {
				escaped = false
				continue
			}
			if r == '\\' {
				escaped = true
				continue
			}
			if r == '"' {
				inString = false
			}
			continue
		}
		switch r {
		case '"':
			inString = true
		case '(':
			depth++
		case ')':
			depth--
			if depth < 0 {
				return fmt.Errorf("AST query has unmatched closing parenthesis")
			}
		}
	}
	if inString {
		return fmt.Errorf("AST query has unterminated string literal")
	}
	if depth != 0 {
		return fmt.Errorf("AST query has unmatched opening parenthesis")
	}
	return nil
}

func uniqueStrings(xs []string) []string {
	if len(xs) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		if _, ok := seen[x]; ok {
			continue
		}
		seen[x] = struct{}{}
		out = append(out, x)
	}
	sort.Strings(out)
	return out
}

type QueryMatch struct {
	Captures map[string]Node
}

var textPredicateRE = regexp.MustCompile(`\(#(eq\?|match\?|not-eq\?|not-match\?)\s+(@[A-Za-z_][A-Za-z0-9_]*)\s+"((?:\\.|[^"\\])*)"\s*\)`)

func parseTextPredicates(source string) ([]TextPredicate, error) {
	var out []TextPredicate
	for _, m := range textPredicateRE.FindAllStringSubmatch(source, -1) {
		value := strings.ReplaceAll(m[3], `\"`, `"`)
		value = strings.ReplaceAll(value, `\\`, `\`)
		out = append(out, TextPredicate{
			Op:      m[1],
			Capture: m[2],
			Value:   value,
		})
	}
	return out, nil
}
