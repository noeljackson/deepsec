package scanner

import (
	"strings"
	"testing"
)

func TestCompileASTPattern(t *testing.T) {
	m, err := Compile(MatcherDef{
		Slug:         "ast-test",
		Description:  "test",
		FilePatterns: []string{"**/*.go"},
		ASTPatterns: []ASTPatternDef{{
			Language:          "go",
			Query:             `((call_expression) @call (#eq? @call "x"))`,
			PrimaryCapture:    "@call",
			SnippetCapture:    "@call",
			PrefilterPatterns: []string{`exec\.Command`},
		}},
	})
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	if !m.HasASTPatterns() {
		t.Fatal("compiled matcher does not report AST patterns")
	}
	if got := m.ASTLanguages(); len(got) != 1 || got[0] != "go" {
		t.Fatalf("ASTLanguages() = %#v", got)
	}
}

func TestCompileRejectsMissingPrimaryCapture(t *testing.T) {
	_, err := Compile(MatcherDef{
		Slug:         "ast-test",
		Description:  "test",
		FilePatterns: []string{"**/*.go"},
		ASTPatterns: []ASTPatternDef{{
			Language:       "go",
			Query:          `((call_expression) @call)`,
			PrimaryCapture: "@match",
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "primary_capture") {
		t.Fatalf("Compile() error = %v, want primary_capture failure", err)
	}
}

func TestRegistryTracksASTPatterns(t *testing.T) {
	reg := NewRegistry()
	m, err := Compile(MatcherDef{
		Slug:         "ast-test",
		Description:  "test",
		FilePatterns: []string{"**/*.go"},
		ASTPatterns: []ASTPatternDef{{
			Language:       "go",
			Query:          `((call_expression) @match)`,
			PrimaryCapture: "@match",
		}},
	})
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	reg.Register(m)
	if !reg.HasASTPatterns() {
		t.Fatal("registry did not track AST pattern")
	}
	reg.ApplyFilter([]string{"other"}, nil)
	if reg.HasASTPatterns() {
		t.Fatal("registry still reports AST after filter removed matcher")
	}
}
