package ast

import (
	"context"
	"errors"
	"sort"
	"testing"
	"time"
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

func TestWazeroBridgeParsesGo(t *testing.T) {
	rt, err := NewRuntime(context.Background(), DefaultGrammars())
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	defer rt.Close(context.Background())
	tree, err := rt.Parse(context.Background(), LanguageGo, []byte("package main\n\nfunc main() {\n\tprintln(\"ok\")\n}\n"), "main.go")
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	defer tree.Close()
	root := tree.Root()
	if root.Kind() != "source_file" {
		t.Fatalf("root kind = %q, want source_file", root.Kind())
	}
	children := root.NamedChildren()
	if len(children) < 2 {
		t.Fatalf("root named children = %d, want at least 2", len(children))
	}
	if got := children[0].Kind(); got != "package_clause" {
		t.Fatalf("first child kind = %q, want package_clause", got)
	}
	if rng := children[1].Range(); rng.StartLine != 3 {
		t.Fatalf("function range start line = %d, want 3", rng.StartLine)
	}
}

func TestWazeroBridgeRunsQuery(t *testing.T) {
	rt, err := NewRuntime(context.Background(), DefaultGrammars())
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	defer rt.Close(context.Background())
	tree, err := rt.Parse(context.Background(), LanguageGo, []byte("package main\n\nfunc run() { exec.Command(\"sh\", \"-c\", \"id \"+user) }\n"), "main.go")
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	defer tree.Close()
	q, err := ParseQuery(LanguageGo, `
(
  call_expression
    function: (selector_expression
      operand: (identifier) @pkg
      field: (field_identifier) @method)
    arguments: (argument_list
      (interpreted_string_literal)
      (interpreted_string_literal)
      (binary_expression) @arg)
) @call
(#eq? @pkg "exec")
(#eq? @method "Command")
`)
	if err != nil {
		t.Fatalf("ParseQuery() error = %v", err)
	}
	matches, err := ExecuteQuery(context.Background(), tree, q)
	if err != nil {
		t.Fatalf("ExecuteQuery() error = %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("matches = %d, want 1", len(matches))
	}
	if got := matches[0].Captures["@arg"].Kind(); got != "binary_expression" {
		t.Fatalf("@arg kind = %q, want binary_expression", got)
	}
}

func TestWazeroBridgeFreesMemory(t *testing.T) {
	rt, err := NewRuntime(context.Background(), DefaultGrammars())
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	defer rt.Close(context.Background())
	for i := 0; i < 2; i++ {
		tree, err := rt.Parse(context.Background(), LanguageGo, []byte("package main\nfunc main() {}\n"), "main.go")
		if err != nil {
			t.Fatalf("Parse round %d error = %v", i+1, err)
		}
		tree.Close()
	}
}

func BenchmarkASTParse_Go(b *testing.B) {
	rt, err := NewRuntime(context.Background(), DefaultGrammars())
	if err != nil {
		b.Fatalf("NewRuntime() error = %v", err)
	}
	defer rt.Close(context.Background())
	content := []byte(goSample500LOC())
	b.ReportAllocs()
	durations := make([]time.Duration, 0, b.N)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		start := time.Now()
		tree, err := rt.Parse(context.Background(), LanguageGo, content, "sample.go")
		if err != nil {
			b.Fatal(err)
		}
		tree.Close()
		durations = append(durations, time.Since(start))
	}
	b.StopTimer()
	if len(durations) > 0 {
		sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
		p50 := durations[len(durations)/2]
		p95 := durations[(len(durations)*95)/100]
		b.ReportMetric(float64(p50)/float64(time.Millisecond), "p50_ms")
		b.ReportMetric(float64(p95)/float64(time.Millisecond), "p95_ms")
	}
}

func goSample500LOC() string {
	out := "package main\n\nfunc sample() {\n"
	for i := 0; i < 248; i++ {
		out += "\t_ = 1\n"
		out += "\t// scanner budget sample\n"
	}
	out += "}\n"
	return out
}
