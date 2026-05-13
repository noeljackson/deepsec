package ast

import (
	"path/filepath"
	"strings"
)

// Language is the internal AST routing language. TSX/JSX stay distinct
// here even though user-facing scan stats continue grouping them with TS/JS.
type Language string

const (
	LanguageGo         Language = "go"
	LanguageJavaScript Language = "javascript"
	LanguageJSX        Language = "jsx"
	LanguageTypeScript Language = "typescript"
	LanguageTSX        Language = "tsx"
	LanguagePython     Language = "python"
	LanguageRust       Language = "rust"
	LanguageJava       Language = "java"
)

var supported = map[Language]struct{}{
	LanguageGo:         {},
	LanguageJavaScript: {},
	LanguageJSX:        {},
	LanguageTypeScript: {},
	LanguageTSX:        {},
	LanguagePython:     {},
	LanguageRust:       {},
	LanguageJava:       {},
}

func IsSupported(lang Language) bool {
	_, ok := supported[lang]
	return ok
}

func SupportedLanguages() []Language {
	return []Language{
		LanguageGo,
		LanguageJavaScript,
		LanguageJSX,
		LanguageTypeScript,
		LanguageTSX,
		LanguagePython,
		LanguageRust,
		LanguageJava,
	}
}

func LanguageForPath(path string) Language {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".go":
		return LanguageGo
	case ".ts":
		return LanguageTypeScript
	case ".tsx":
		return LanguageTSX
	case ".js", ".mjs", ".cjs":
		return LanguageJavaScript
	case ".jsx":
		return LanguageJSX
	case ".py":
		return LanguagePython
	case ".rs":
		return LanguageRust
	case ".java":
		return LanguageJava
	default:
		return ""
	}
}

type Range struct {
	StartByte int
	EndByte   int
	StartLine int
	EndLine   int
}

type Node interface {
	Kind() string
	Range() Range
	NamedChildren() []Node
	NamedChildByFieldName(name string) (Node, bool)
	Text() string
}

type Tree interface {
	Root() Node
	Language() Language
	FilePath() string
	Content() string
	Source() []byte
	RootRange() Range
	Close()
}

type SourceTree struct {
	lang     Language
	filePath string
	content  string
}

func NewSourceTree(lang Language, filePath, content string) *SourceTree {
	return &SourceTree{lang: lang, filePath: filePath, content: content}
}

func (t *SourceTree) Language() Language { return t.lang }
func (t *SourceTree) FilePath() string   { return t.filePath }
func (t *SourceTree) Content() string    { return t.content }
func (t *SourceTree) Source() []byte     { return []byte(t.content) }
func (t *SourceTree) Close()             {}
func (t *SourceTree) Root() Node {
	return NewSourceNode(t, t.RootRange(), "source_file")
}
func (t *SourceTree) RootRange() Range {
	return Range{
		StartByte: 0,
		EndByte:   len(t.content),
		StartLine: 1,
		EndLine:   1 + strings.Count(t.content, "\n"),
	}
}

type SourceNode struct {
	tree  *SourceTree
	rng   Range
	label string
}

func NewSourceNode(tree *SourceTree, rng Range, label string) SourceNode {
	return SourceNode{tree: tree, rng: rng, label: label}
}

func (n SourceNode) Range() Range { return n.rng }
func (n SourceNode) Kind() string { return n.label }
func (n SourceNode) NamedChildren() []Node {
	return nil
}
func (n SourceNode) NamedChildByFieldName(name string) (Node, bool) {
	return nil, false
}
func (n SourceNode) Text() string {
	if n.tree == nil {
		return ""
	}
	start := n.rng.StartByte
	end := n.rng.EndByte
	if start < 0 {
		start = 0
	}
	if end > len(n.tree.content) {
		end = len(n.tree.content)
	}
	if start > end {
		return ""
	}
	return n.tree.content[start:end]
}

func (n SourceNode) Label() string { return n.label }
