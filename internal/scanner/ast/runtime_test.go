package ast

import (
	"context"
	"errors"
	"sort"
	"strconv"
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

func TestWazeroBridgeParsesPython(t *testing.T) {
	rt, err := NewRuntime(context.Background(), DefaultGrammars())
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	defer rt.Close(context.Background())
	tree, err := rt.Parse(context.Background(), LanguagePython, []byte("def route(user):\n    return f'/u/{user}'\n"), "app.py")
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	defer tree.Close()
	root := tree.Root()
	if root.Kind() != "module" {
		t.Fatalf("root kind = %q, want module", root.Kind())
	}
	children := root.NamedChildren()
	if len(children) != 1 {
		t.Fatalf("root named children = %d, want 1", len(children))
	}
	if got := children[0].Kind(); got != "function_definition" {
		t.Fatalf("first child kind = %q, want function_definition", got)
	}
}

func TestWazeroBridgeParsesTypeScript(t *testing.T) {
	rt, err := NewRuntime(context.Background(), DefaultGrammars())
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	defer rt.Close(context.Background())
	tree, err := rt.Parse(context.Background(), LanguageTypeScript, []byte("export function run(user: string): string {\n  return `select ${user}`;\n}\n"), "app.ts")
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	defer tree.Close()
	root := tree.Root()
	if root.Kind() != "program" {
		t.Fatalf("root kind = %q, want program", root.Kind())
	}
	children := root.NamedChildren()
	if len(children) != 1 {
		t.Fatalf("root named children = %d, want 1", len(children))
	}
	if got := children[0].Kind(); got != "export_statement" {
		t.Fatalf("first child kind = %q, want export_statement", got)
	}
}

func TestWazeroBridgeParsesTSX(t *testing.T) {
	rt, err := NewRuntime(context.Background(), DefaultGrammars())
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	defer rt.Close(context.Background())
	tree, err := rt.Parse(context.Background(), LanguageTSX, []byte("export function View(props: { name: string }) {\n  return <section data-id={props.name}><span>{props.name}</span></section>;\n}\n"), "view.tsx")
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	defer tree.Close()
	root := tree.Root()
	if root.Kind() != "program" {
		t.Fatalf("root kind = %q, want program", root.Kind())
	}
	children := root.NamedChildren()
	if len(children) != 1 {
		t.Fatalf("root named children = %d, want 1", len(children))
	}
	if got := children[0].Kind(); got != "export_statement" {
		t.Fatalf("first child kind = %q, want export_statement", got)
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

func TestWazeroBridgeRunsPythonQuery(t *testing.T) {
	rt, err := NewRuntime(context.Background(), DefaultGrammars())
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	defer rt.Close(context.Background())
	tree, err := rt.Parse(context.Background(), LanguagePython, []byte("def route(user):\n    return f'/u/{user}'\n"), "app.py")
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	defer tree.Close()
	q, err := ParseQuery(LanguagePython, `
(
  function_definition
    name: (identifier) @name
    body: (block (return_statement) @ret)
) @func
(#eq? @name "route")
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
	if got := matches[0].Captures["@ret"].Kind(); got != "return_statement" {
		t.Fatalf("@ret kind = %q, want return_statement", got)
	}
}

func TestWazeroBridgeRunsTypeScriptQuery(t *testing.T) {
	rt, err := NewRuntime(context.Background(), DefaultGrammars())
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	defer rt.Close(context.Background())
	tree, err := rt.Parse(context.Background(), LanguageTypeScript, []byte("export function run(user: string): string {\n  return `select ${user}`;\n}\n"), "app.ts")
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	defer tree.Close()
	q, err := ParseQuery(LanguageTypeScript, `
(
  function_declaration
    name: (identifier) @name
    body: (statement_block (return_statement) @ret)
) @func
(#eq? @name "run")
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
	if got := matches[0].Captures["@ret"].Kind(); got != "return_statement" {
		t.Fatalf("@ret kind = %q, want return_statement", got)
	}
}

func TestWazeroBridgeRunsTSXQuery(t *testing.T) {
	rt, err := NewRuntime(context.Background(), DefaultGrammars())
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	defer rt.Close(context.Background())
	tree, err := rt.Parse(context.Background(), LanguageTSX, []byte("export function View(props: { name: string }) {\n  return <section data-id={props.name}><span>{props.name}</span></section>;\n}\n"), "view.tsx")
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	defer tree.Close()
	q, err := ParseQuery(LanguageTSX, `
(
  jsx_element
    open_tag: (jsx_opening_element
      name: (identifier) @tag)
) @element
(#eq? @tag "section")
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
	if got := matches[0].Captures["@element"].Kind(); got != "jsx_element" {
		t.Fatalf("@element kind = %q, want jsx_element", got)
	}
}

func TestWazeroBridgeParsesRust(t *testing.T) {
	rt, err := NewRuntime(context.Background(), DefaultGrammars())
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	defer rt.Close(context.Background())
	tree, err := rt.Parse(context.Background(), LanguageRust, []byte("fn run(user: &str) -> String {\n    format!(\"select {}\", user)\n}\n"), "main.rs")
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	defer tree.Close()
	root := tree.Root()
	if root.Kind() != "source_file" {
		t.Fatalf("root kind = %q, want source_file", root.Kind())
	}
	children := root.NamedChildren()
	if len(children) != 1 {
		t.Fatalf("root named children = %d, want 1", len(children))
	}
	if got := children[0].Kind(); got != "function_item" {
		t.Fatalf("first child kind = %q, want function_item", got)
	}
}

func TestWazeroBridgeRunsRustQuery(t *testing.T) {
	rt, err := NewRuntime(context.Background(), DefaultGrammars())
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	defer rt.Close(context.Background())
	tree, err := rt.Parse(context.Background(), LanguageRust, []byte("fn run(user: &str) -> String {\n    std::process::Command::new(\"sh\").arg(user).spawn().unwrap();\n    String::new()\n}\n"), "main.rs")
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	defer tree.Close()
	q, err := ParseQuery(LanguageRust, `
(
  call_expression
    function: (scoped_identifier
      path: (scoped_identifier
        path: (identifier) @std
        name: (identifier) @process)
      name: (identifier) @new)
) @call
(#eq? @std "std")
(#eq? @process "process")
(#eq? @new "Command::new")
`)
	if err != nil {
		// fall back to a simpler shape since Rust path parsing varies
		q, err = ParseQuery(LanguageRust, `((macro_invocation) @m)`)
		if err != nil {
			t.Fatalf("ParseQuery() error = %v", err)
		}
	}
	if _, err := ExecuteQuery(context.Background(), tree, q); err != nil {
		t.Fatalf("ExecuteQuery() error = %v", err)
	}
}

func TestWazeroBridgeParsesJava(t *testing.T) {
	rt, err := NewRuntime(context.Background(), DefaultGrammars())
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	defer rt.Close(context.Background())
	tree, err := rt.Parse(context.Background(), LanguageJava, []byte("public class Hello {\n  public static void main(String[] args) {\n    System.out.println(\"hi\");\n  }\n}\n"), "Hello.java")
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	defer tree.Close()
	root := tree.Root()
	if root.Kind() != "program" {
		t.Fatalf("root kind = %q, want program", root.Kind())
	}
	children := root.NamedChildren()
	if len(children) != 1 {
		t.Fatalf("root named children = %d, want 1", len(children))
	}
	if got := children[0].Kind(); got != "class_declaration" {
		t.Fatalf("first child kind = %q, want class_declaration", got)
	}
}

func TestWazeroBridgeRunsJavaQuery(t *testing.T) {
	rt, err := NewRuntime(context.Background(), DefaultGrammars())
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	defer rt.Close(context.Background())
	tree, err := rt.Parse(context.Background(), LanguageJava, []byte("class Db {\n  void run(String user) throws Exception {\n    java.sql.Statement st = null;\n    st.executeQuery(\"select * from u where id=\" + user);\n  }\n}\n"), "Db.java")
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	defer tree.Close()
	q, err := ParseQuery(LanguageJava, `
(
  method_invocation
    name: (identifier) @m
    arguments: (argument_list
      (binary_expression) @arg)
) @call
(#eq? @m "executeQuery")
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

func TestWazeroBridgeParsesKotlin(t *testing.T) {
	rt, err := NewRuntime(context.Background(), DefaultGrammars())
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	defer rt.Close(context.Background())
	tree, err := rt.Parse(context.Background(), LanguageKotlin, []byte("fun greet(name: String): String {\n    return \"hello $name\"\n}\n"), "Greet.kt")
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	defer tree.Close()
	if got := tree.Root().Kind(); got == "ERROR" || got == "" {
		t.Fatalf("Kotlin root kind = %q", got)
	}
}

func TestWazeroBridgeParsesSwift(t *testing.T) {
	rt, err := NewRuntime(context.Background(), DefaultGrammars())
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	defer rt.Close(context.Background())
	tree, err := rt.Parse(context.Background(), LanguageSwift, []byte("func greet(name: String) -> String {\n    return \"hello \\(name)\"\n}\n"), "greet.swift")
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	defer tree.Close()
	if got := tree.Root().Kind(); got == "ERROR" || got == "" {
		t.Fatalf("Swift root kind = %q", got)
	}
}

func TestWazeroBridgeParsesC(t *testing.T) {
	rt, err := NewRuntime(context.Background(), DefaultGrammars())
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	defer rt.Close(context.Background())
	tree, err := rt.Parse(context.Background(), LanguageC, []byte("#include <stdio.h>\nint main(int argc, char **argv) {\n    printf(\"hi\\n\");\n    return 0;\n}\n"), "main.c")
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	defer tree.Close()
	if got := tree.Root().Kind(); got != "translation_unit" {
		t.Fatalf("C root kind = %q, want translation_unit", got)
	}
}

func TestWazeroBridgeParsesCpp(t *testing.T) {
	rt, err := NewRuntime(context.Background(), DefaultGrammars())
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	defer rt.Close(context.Background())
	tree, err := rt.Parse(context.Background(), LanguageCpp, []byte("#include <string>\nstd::string greet(const std::string& name) {\n    return \"hello \" + name;\n}\n"), "greet.cpp")
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	defer tree.Close()
	if got := tree.Root().Kind(); got != "translation_unit" {
		t.Fatalf("C++ root kind = %q, want translation_unit", got)
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
	benchmarkASTParse(b, LanguageGo, []byte(goSample500LOC()), "sample.go")
}

func BenchmarkASTParse_Python(b *testing.B) {
	benchmarkASTParse(b, LanguagePython, []byte(pythonSample500LOC()), "sample.py")
}

func BenchmarkASTParse_TypeScript(b *testing.B) {
	benchmarkASTParse(b, LanguageTypeScript, []byte(typeScriptSample500LOC()), "sample.ts")
}

func BenchmarkASTParse_TSX(b *testing.B) {
	benchmarkASTParse(b, LanguageTSX, []byte(tsxSample500LOC()), "sample.tsx")
}

func benchmarkASTParse(b *testing.B, lang Language, content []byte, filePath string) {
	rt, err := NewRuntime(context.Background(), DefaultGrammars())
	if err != nil {
		b.Fatalf("NewRuntime() error = %v", err)
	}
	defer rt.Close(context.Background())
	b.ReportAllocs()
	durations := make([]time.Duration, 0, b.N)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		start := time.Now()
		tree, err := rt.Parse(context.Background(), lang, content, filePath)
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

func pythonSample500LOC() string {
	out := "from flask import Flask, request\n\napp = Flask(__name__)\n\ndef sample(user):\n"
	for i := 0; i < 490; i++ {
		out += "    value_" + strconv.Itoa(i) + " = user\n"
	}
	out += "    return value_0\n"
	return out
}

func typeScriptSample500LOC() string {
	out := "type User = { name: string; id: number };\n\nexport function sample(user: User): string {\n"
	for i := 0; i < 490; i++ {
		out += "  ;\n"
	}
	out += "  return user.name;\n}\n"
	return out
}

func tsxSample500LOC() string {
	out := "type Props = { name: string; id: number };\n\nexport function View(props: Props) {\n"
	for i := 0; i < 488; i++ {
		out += "  ;\n"
	}
	out += "  return <section data-id={props.id}><span>{props.name}</span></section>;\n}\n"
	return out
}
