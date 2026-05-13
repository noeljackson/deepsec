package ast

import (
	"context"
	"errors"
	"testing"
)

func TestRuntimeUnavailableGrammar(t *testing.T) {
	rt, err := NewRuntime(context.Background(), nil)
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	defer rt.Close(context.Background())
	_, err = rt.Parse(context.Background(), LanguageGo, []byte("package main\n"), "main.go")
	if !errors.Is(err, ErrLanguageUnavailable) {
		t.Fatalf("Parse() error = %v, want ErrLanguageUnavailable", err)
	}
}

func BenchmarkASTParse(b *testing.B) {
	rt, err := NewRuntime(context.Background(), nil)
	if err != nil {
		b.Fatalf("NewRuntime() error = %v", err)
	}
	defer rt.Close(context.Background())
	if !rt.HasGrammar(LanguageGo) {
		b.Skip("tree-sitter grammar WASM artifacts are not committed yet")
	}
	content := []byte(repeatLines("package main\nfunc handler() {}\n", 250))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := rt.Parse(context.Background(), LanguageGo, content, "sample.go"); err != nil {
			b.Fatal(err)
		}
	}
}

func repeatLines(line string, n int) string {
	out := make([]byte, 0, len(line)*n)
	for i := 0; i < n; i++ {
		out = append(out, line...)
	}
	return string(out)
}
