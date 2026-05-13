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

func DefaultGrammars() []Grammar {
	return []Grammar{{
		Language: LanguageGo,
		Version:  "tree-sitter-go@0.25.0",
		WASM:     treeSitterGoWASM,
	}}
}
