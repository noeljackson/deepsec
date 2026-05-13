package ast

import _ "embed"

// Tree-sitter Go grammar procured from npm package tree-sitter-go@0.25.0.
//
// To refresh:
//
//	npm pack tree-sitter-go@0.25.0
//	tar -xzf tree-sitter-go-0.25.0.tgz package/tree-sitter-go.wasm
//
//go:embed grammars/tree-sitter-go.wasm
var treeSitterGoWASM []byte

// Tree-sitter Python grammar procured from npm package tree-sitter-python@0.25.0.
//
// To refresh:
//
//	npm pack tree-sitter-python@0.25.0
//	tar -xzf tree-sitter-python-0.25.0.tgz package/tree-sitter-python.wasm
//
//go:embed grammars/tree-sitter-python.wasm
var treeSitterPythonWASM []byte

// Tree-sitter TypeScript grammars procured from npm package
// tree-sitter-typescript@0.23.2.
//
// To refresh:
//
//	npm pack tree-sitter-typescript@0.23.2
//	tar -xzf tree-sitter-typescript-0.23.2.tgz package/tree-sitter-typescript.wasm package/tree-sitter-tsx.wasm
//
//go:embed grammars/tree-sitter-typescript.wasm
var treeSitterTypeScriptWASM []byte

//go:embed grammars/tree-sitter-tsx.wasm
var treeSitterTSXWASM []byte

// Tree-sitter Rust grammar procured from npm package tree-sitter-rust@0.24.0.
//
// To refresh:
//
//	npm pack tree-sitter-rust@0.24.0
//	tar -xzf tree-sitter-rust-0.24.0.tgz package/tree-sitter-rust.wasm
//
//go:embed grammars/tree-sitter-rust.wasm
var treeSitterRustWASM []byte

// Tree-sitter Java grammar procured from npm package tree-sitter-java@0.23.5.
//
// To refresh:
//
//	npm pack tree-sitter-java@0.23.5
//	tar -xzf tree-sitter-java-0.23.5.tgz package/tree-sitter-java.wasm
//
//go:embed grammars/tree-sitter-java.wasm
var treeSitterJavaWASM []byte

func DefaultGrammars() []Grammar {
	return []Grammar{
		{
			Language: LanguageGo,
			Version:  "tree-sitter-go@0.25.0",
			WASM:     treeSitterGoWASM,
		},
		{
			Language: LanguagePython,
			Version:  "tree-sitter-python@0.25.0",
			WASM:     treeSitterPythonWASM,
		},
		{
			Language: LanguageTypeScript,
			Version:  "tree-sitter-typescript@0.23.2",
			WASM:     treeSitterTypeScriptWASM,
		},
		{
			Language:  LanguageJavaScript,
			Version:   "tree-sitter-typescript@0.23.2",
			WASM:      treeSitterTypeScriptWASM,
			EntryName: "typescript",
		},
		{
			Language: LanguageTSX,
			Version:  "tree-sitter-tsx@0.23.2",
			WASM:     treeSitterTSXWASM,
		},
		{
			Language:  LanguageJSX,
			Version:   "tree-sitter-tsx@0.23.2",
			WASM:      treeSitterTSXWASM,
			EntryName: "tsx",
		},
		{
			Language: LanguageRust,
			Version:  "tree-sitter-rust@0.24.0",
			WASM:     treeSitterRustWASM,
		},
		{
			Language: LanguageJava,
			Version:  "tree-sitter-java@0.23.5",
			WASM:     treeSitterJavaWASM,
		},
	}
}
