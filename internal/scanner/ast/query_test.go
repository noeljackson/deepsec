package ast

import (
	"strings"
	"testing"
)

func TestParseQueryCapturesAndPredicates(t *testing.T) {
	q, err := ParseQuery(LanguageGo, `
(
  call_expression
    function: (selector_expression
      operand: (identifier) @pkg
      field: (field_identifier) @method)
) @call
(#eq? @pkg "exec")
(#match? @method "^(Command|CommandContext)$")
`)
	if err != nil {
		t.Fatalf("ParseQuery() error = %v", err)
	}
	for _, capture := range []string{"@call", "@pkg", "@method"} {
		if !q.HasCapture(capture) {
			t.Fatalf("expected capture %s in %#v", capture, q.Captures)
		}
	}
	if len(q.Predicates) != 2 {
		t.Fatalf("predicates = %#v, want two predicates", q.Predicates)
	}
}

func TestParseQueryRejectsUnsupportedPredicate(t *testing.T) {
	_, err := ParseQuery(LanguagePython, `((call) @match (#any-of? @match "x"))`)
	if err == nil || !strings.Contains(err.Error(), "unsupported AST query predicate") {
		t.Fatalf("ParseQuery() error = %v, want unsupported predicate", err)
	}
}

func TestParseQueryRejectsUnbalancedParens(t *testing.T) {
	_, err := ParseQuery(LanguageTSX, `((jsx_attribute) @match`)
	if err == nil || !strings.Contains(err.Error(), "unmatched opening") {
		t.Fatalf("ParseQuery() error = %v, want unmatched opening", err)
	}
}

func TestLanguageForPathSplitsJSXAndTSX(t *testing.T) {
	cases := map[string]Language{
		"app.go":        LanguageGo,
		"view.ts":       LanguageTypeScript,
		"view.tsx":      LanguageTSX,
		"component.js":  LanguageJavaScript,
		"component.jsx": LanguageJSX,
		"server.py":     LanguagePython,
		"src/main.rs":   LanguageRust,
		"Hello.java":    LanguageJava,
	}
	for path, want := range cases {
		if got := LanguageForPath(path); got != want {
			t.Fatalf("LanguageForPath(%q) = %q, want %q", path, got, want)
		}
	}
}
