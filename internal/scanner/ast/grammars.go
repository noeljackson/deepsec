package ast

import _ "embed"

// Every grammar is built locally via scripts/build-grammar-wasm.sh
// from its upstream npm tree-sitter-<lang> package, inside a pinned
// emscripten/emsdk docker image, using a pinned tree-sitter-cli
// version. The resulting WASMs are wasi-sdk-style (dynamic-link with
// a dylink.0 section, env imports for memory + table + libc), loaded
// by the bridge in wazero_abi.go. See docs/refreshing-grammars.md.

//go:embed grammars/tree-sitter-go.wasm
var treeSitterGoWASM []byte

//go:embed grammars/tree-sitter-python.wasm
var treeSitterPythonWASM []byte

//go:embed grammars/tree-sitter-typescript.wasm
var treeSitterTypeScriptWASM []byte

//go:embed grammars/tree-sitter-tsx.wasm
var treeSitterTSXWASM []byte

//go:embed grammars/tree-sitter-rust.wasm
var treeSitterRustWASM []byte

//go:embed grammars/tree-sitter-java.wasm
var treeSitterJavaWASM []byte

//go:embed grammars/tree-sitter-kotlin.wasm
var treeSitterKotlinWASM []byte

//go:embed grammars/tree-sitter-swift.wasm
var treeSitterSwiftWASM []byte

//go:embed grammars/tree-sitter-c.wasm
var treeSitterCWASM []byte

//go:embed grammars/tree-sitter-cpp.wasm
var treeSitterCppWASM []byte

func DefaultGrammars() []Grammar {
	return []Grammar{
		{Language: LanguageGo, Version: "tree-sitter-go@0.25.0", WASM: treeSitterGoWASM},
		{Language: LanguagePython, Version: "tree-sitter-python@0.25.0", WASM: treeSitterPythonWASM},
		{Language: LanguageTypeScript, Version: "tree-sitter-typescript@0.23.2", WASM: treeSitterTypeScriptWASM},
		// JavaScript files (.js/.mjs/.cjs) reuse the TypeScript grammar — the
		// constructor symbol exported by the WASM is `tree_sitter_typescript`.
		{Language: LanguageJavaScript, Version: "tree-sitter-typescript@0.23.2", WASM: treeSitterTypeScriptWASM, EntryName: "typescript"},
		{Language: LanguageTSX, Version: "tree-sitter-typescript@0.23.2 (tsx subgrammar)", WASM: treeSitterTSXWASM},
		// JSX files reuse the TSX grammar.
		{Language: LanguageJSX, Version: "tree-sitter-typescript@0.23.2 (tsx subgrammar)", WASM: treeSitterTSXWASM, EntryName: "tsx"},
		{Language: LanguageRust, Version: "tree-sitter-rust@0.24.0", WASM: treeSitterRustWASM},
		{Language: LanguageJava, Version: "tree-sitter-java@0.23.5", WASM: treeSitterJavaWASM},
		{Language: LanguageKotlin, Version: "tree-sitter-kotlin@0.3.8", WASM: treeSitterKotlinWASM},
		{Language: LanguageSwift, Version: "tree-sitter-swift@0.7.1", WASM: treeSitterSwiftWASM},
		{Language: LanguageC, Version: "tree-sitter-c@0.24.1", WASM: treeSitterCWASM},
		{Language: LanguageCpp, Version: "tree-sitter-cpp@0.23.4", WASM: treeSitterCppWASM},
	}
}
