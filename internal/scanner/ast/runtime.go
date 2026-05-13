package ast

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/tetratelabs/wazero"
)

var ErrLanguageUnavailable = errors.New("AST grammar wasm unavailable")
var ErrParserAdapterUnavailable = errors.New("AST parser wasm ABI adapter unavailable")

type Grammar struct {
	Language Language
	Version  string
	WASM     []byte
}

type Runtime struct {
	mu       sync.Mutex
	rt       wazero.Runtime
	grammars map[Language]Grammar
	compiled map[Language]wazero.CompiledModule
	wasm     *wasmRuntime
}

func NewRuntime(ctx context.Context, grammars []Grammar) (*Runtime, error) {
	r := &Runtime{
		rt:       wazero.NewRuntime(ctx),
		grammars: map[Language]Grammar{},
		compiled: map[Language]wazero.CompiledModule{},
	}
	for _, g := range grammars {
		if !IsSupported(g.Language) {
			_ = r.rt.Close(ctx)
			return nil, fmt.Errorf("unsupported AST grammar language %q", g.Language)
		}
		if len(g.WASM) == 0 {
			continue
		}
		r.grammars[g.Language] = g
	}
	return r, nil
}

func (r *Runtime) Close(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.rt == nil {
		return nil
	}
	err := r.rt.Close(ctx)
	r.rt = nil
	return err
}

func (r *Runtime) HasGrammar(lang Language) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.grammars[lang]
	return ok
}

func (r *Runtime) GrammarVersion(lang Language) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	g, ok := r.grammars[lang]
	if !ok {
		return ""
	}
	return g.Version
}

func (r *Runtime) ensureCompiled(ctx context.Context, lang Language) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.rt == nil {
		return fmt.Errorf("AST runtime closed")
	}
	if _, ok := r.compiled[lang]; ok {
		return nil
	}
	g, ok := r.grammars[lang]
	if !ok || len(g.WASM) == 0 {
		return fmt.Errorf("%w: %s", ErrLanguageUnavailable, lang)
	}
	mod, err := r.rt.CompileModule(ctx, g.WASM)
	if err != nil {
		return fmt.Errorf("compile %s AST grammar wasm: %w", lang, err)
	}
	r.compiled[lang] = mod
	return nil
}

func (r *Runtime) Parse(ctx context.Context, lang Language, content []byte, filePath string) (Tree, error) {
	if !IsSupported(lang) {
		return nil, fmt.Errorf("unsupported AST language %q", lang)
	}
	g, ok := r.grammars[lang]
	if !ok || len(g.WASM) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrLanguageUnavailable, lang)
	}
	wasm, err := r.ensureWASM(ctx)
	if err != nil {
		return nil, err
	}
	return wasm.parse(ctx, r.rt, g, content, filePath)
}
