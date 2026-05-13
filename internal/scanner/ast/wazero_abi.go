package ast

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"regexp"
	"sync"
	"unicode"

	_ "embed"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

// web-tree-sitter.wasm is from npm package web-tree-sitter@0.26.8.
// tree-sitter-env.wasm and tree-sitter-gotmem.wasm are tiny adapter modules
// that provide the Emscripten imports used by web-tree-sitter.
//
//go:embed wasm/web-tree-sitter.wasm
var webTreeSitterWASM []byte

//go:embed wasm/tree-sitter-env.wasm
var treeSitterEnvWASM []byte

//go:embed wasm/tree-sitter-gotmem.wasm
var treeSitterGotMemWASM []byte

const (
	transferLanguageVersion = 15
	transferMinVersion      = 13
	sizeOfInt               = 4
	sizeOfPoint             = 8
	sizeOfNode              = 20
	inputBufferSize         = 10 * 1024
)

type wasmRuntime struct {
	mu            sync.Mutex
	core          api.Module
	env           api.Module
	transfer      uint32
	currentSource string
	currentUTF16  []uint32
	languages     map[Language]*wasmLanguage
}

type wasmLanguage struct {
	lang      Language
	ptr       uint32
	version   int
	symbols   map[uint32]string
	fieldIDs  map[string]uint32
	bridgeMod api.Module
	parser    uint32
	parserBuf uint32
}

type wasmTree struct {
	rt       *wasmRuntime
	lang     *wasmLanguage
	treePtr  uint32
	filePath string
	content  string
	utf16    []uint32
}

type wasmNode struct {
	tree       *wasmTree
	id         uint32
	startIndex uint32
	startRow   uint32
	startCol   uint32
	other      uint32
}

func (r *Runtime) ensureWASM(ctx context.Context) (*wasmRuntime, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.wasm != nil {
		return r.wasm, nil
	}
	if r.rt == nil {
		return nil, fmt.Errorf("AST runtime closed")
	}
	w := &wasmRuntime{languages: map[Language]*wasmLanguage{}}
	if err := w.instantiate(ctx, r.rt); err != nil {
		return nil, err
	}
	r.wasm = w
	return w, nil
}

func (w *wasmRuntime) instantiate(ctx context.Context, rt wazero.Runtime) error {
	host := rt.NewHostModuleBuilder("deepsec_host")
	host.NewFunctionBuilder().WithFunc(w.resizeHeap).Export("emscripten_resize_heap")
	host.NewFunctionBuilder().WithFunc(func(context.Context) {}).Export("_abort_js")
	host.NewFunctionBuilder().WithFunc(func(context.Context, uint32) uint32 { return 0 }).Export("tree_sitter_query_progress_callback")
	host.NewFunctionBuilder().WithFunc(func(context.Context, uint32, uint32) uint32 { return 0 }).Export("tree_sitter_progress_callback")
	host.NewFunctionBuilder().WithFunc(w.parseCallback).Export("tree_sitter_parse_callback")
	host.NewFunctionBuilder().WithFunc(func(context.Context, uint32, uint32) {}).Export("tree_sitter_log_callback")
	if _, err := host.Instantiate(ctx); err != nil {
		return fmt.Errorf("instantiate tree-sitter host imports: %w", err)
	}
	if _, err := rt.InstantiateWithConfig(ctx, treeSitterEnvWASM, wazero.NewModuleConfig().WithName("env").WithStartFunctions()); err != nil {
		return fmt.Errorf("instantiate tree-sitter env wasm: %w", err)
	}
	env := rt.Module("env")
	if env == nil {
		return fmt.Errorf("tree-sitter env module missing")
	}
	w.env = env
	if _, err := rt.InstantiateWithConfig(ctx, treeSitterGotMemWASM, wazero.NewModuleConfig().WithName("GOT.mem").WithStartFunctions()); err != nil {
		return fmt.Errorf("instantiate tree-sitter GOT.mem wasm: %w", err)
	}
	wasi_snapshot_preview1.MustInstantiate(ctx, rt)
	if _, err := rt.InstantiateWithConfig(ctx, webTreeSitterWASM, wazero.NewModuleConfig().WithName("tree-sitter-core").WithStartFunctions()); err != nil {
		return fmt.Errorf("instantiate web-tree-sitter wasm: %w", err)
	}
	core := rt.Module("tree-sitter-core")
	if core == nil {
		return fmt.Errorf("tree-sitter core module missing")
	}
	w.core = core
	if err := instantiateLibcHost(ctx, rt); err != nil {
		return err
	}
	if err := w.callVoid(ctx, "__wasm_apply_data_relocs"); err != nil {
		return err
	}
	if err := w.callVoid(ctx, "__wasm_call_ctors"); err != nil {
		return err
	}
	out, err := w.call(ctx, "ts_init")
	if err != nil {
		return err
	}
	w.transfer = uint32(out[0])
	gotVersion, ok := w.mem().ReadUint32Le(w.transfer)
	if !ok {
		return fmt.Errorf("tree-sitter transfer buffer unavailable")
	}
	gotMin, ok := w.mem().ReadUint32Le(w.transfer + sizeOfInt)
	if !ok {
		return fmt.Errorf("tree-sitter transfer buffer unavailable")
	}
	if gotVersion != transferLanguageVersion || gotMin != transferMinVersion {
		return fmt.Errorf("unexpected tree-sitter ABI range %d..%d", gotMin, gotVersion)
	}
	return nil
}

func (w *wasmRuntime) resizeHeap(ctx context.Context, m api.Module, requested uint32) uint32 {
	mem := m.Memory()
	if mem == nil {
		return 0
	}
	if requested <= mem.Size() {
		return 1
	}
	needPages := uint32(math.Ceil(float64(requested-mem.Size()) / 65536.0))
	if _, ok := mem.Grow(needPages); !ok {
		return 0
	}
	return 1
}

func instantiateLibcHost(ctx context.Context, rt wazero.Runtime) error {
	if rt.Module("deepsec_libc") != nil {
		return nil
	}
	host := rt.NewHostModuleBuilder("deepsec_libc")
	host.NewFunctionBuilder().WithFunc(func(_ context.Context, c uint32) uint32 {
		if unicode.IsSpace(rune(c)) {
			return 1
		}
		return 0
	}).Export("iswspace")
	host.NewFunctionBuilder().WithFunc(func(_ context.Context, c uint32) uint32 {
		if unicode.IsLetter(rune(c)) {
			return 1
		}
		return 0
	}).Export("iswalpha")
	host.NewFunctionBuilder().WithFunc(func(_ context.Context, c uint32) uint32 {
		r := rune(c)
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return 1
		}
		return 0
	}).Export("iswalnum")
	host.NewFunctionBuilder().WithFunc(func(_ context.Context, c uint32) uint32 {
		if unicode.IsDigit(rune(c)) {
			return 1
		}
		return 0
	}).Export("iswdigit")
	host.NewFunctionBuilder().WithFunc(func(_ context.Context, c uint32) uint32 {
		if unicode.IsLower(rune(c)) {
			return 1
		}
		return 0
	}).Export("iswlower")
	host.NewFunctionBuilder().WithFunc(func(_ context.Context, c uint32) uint32 {
		if unicode.IsUpper(rune(c)) {
			return 1
		}
		return 0
	}).Export("iswupper")
	host.NewFunctionBuilder().WithFunc(func(_ context.Context, c uint32) uint32 {
		if isASCIIHex(c) {
			return 1
		}
		return 0
	}).Export("iswxdigit")
	host.NewFunctionBuilder().WithFunc(func(_ context.Context, c uint32) uint32 {
		return uint32(unicode.ToLower(rune(c)))
	}).Export("towlower")
	host.NewFunctionBuilder().WithFunc(func(_ context.Context, c uint32) uint32 {
		return uint32(unicode.ToUpper(rune(c)))
	}).Export("towupper")
	// abort and __assert_fail are imported by wasi-sdk-built grammars
	// (the toolchain emits abort() calls on unreachable paths). Treat
	// either as a fatal grammar error — they should never fire during
	// normal parsing, but if they do we want the runtime to fail loudly.
	host.NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module) {
		panic("tree-sitter grammar called abort()")
	}).Export("abort")
	host.NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, _, _, _, _ uint32) {
		panic("tree-sitter grammar __assert_fail (typically a memory-safety violation in the grammar)")
	}).Export("__assert_fail")
	if _, err := host.Instantiate(ctx); err != nil {
		return fmt.Errorf("instantiate grammar libc host imports: %w", err)
	}
	return nil
}

func isASCIIHex(c uint32) bool {
	return ('0' <= c && c <= '9') || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F')
}

func (w *wasmRuntime) parseCallback(ctx context.Context, m api.Module, inputBuffer, index, _, _ uint32, lengthAddr uint32) {
	mem := m.Memory()
	if mem == nil || len(w.currentUTF16) == 0 || index >= uint32(len(w.currentUTF16)-1) {
		_ = mem.WriteUint32Le(lengthAddr, 0)
		return
	}
	src := w.currentSource[w.currentUTF16[index]:]
	units := 0
	off := inputBuffer
	for _, r := range src {
		if off+2 > inputBuffer+inputBufferSize {
			break
		}
		if r > 0xffff {
			if off+4 > inputBuffer+inputBufferSize {
				break
			}
			r -= 0x10000
			_ = mem.WriteUint16Le(off, uint16(0xd800+(r>>10)))
			_ = mem.WriteUint16Le(off+2, uint16(0xdc00+(r&0x3ff)))
			off += 4
			units += 2
			continue
		}
		_ = mem.WriteUint16Le(off, uint16(r))
		off += 2
		units++
	}
	_ = mem.WriteUint32Le(lengthAddr, uint32(units))
}

// grammarStackSize is the stack region (in bytes) allocated per
// grammar for its __stack_pointer. wasi-sdk-built grammars decrement
// the pointer on function entry; 256 KiB has been sufficient in
// practice for every grammar we ship (kotlin/swift/c/cpp use the
// most because their scanner.c does recursive descent).
const grammarStackSize = 256 * 1024

func (w *wasmRuntime) loadLanguage(ctx context.Context, rt wazero.Runtime, g Grammar) (*wasmLanguage, error) {
	if lang := w.languages[g.Language]; lang != nil {
		return lang, nil
	}
	meta, err := readDylink(g.WASM)
	if err != nil {
		return nil, fmt.Errorf("%s grammar dylink metadata: %w", g.Language, err)
	}
	allocSize := meta.memorySize + (1 << meta.memoryAlign)
	memBaseOut, err := w.call(ctx, "calloc", uint64(allocSize), 1)
	if err != nil {
		return nil, err
	}
	memBase := align(uint32(memBaseOut[0]), 1<<meta.memoryAlign)
	tableSize := meta.tableSize + (1 << meta.tableAlign)
	tableBaseOut, err := w.env.ExportedFunction("grow_table").Call(ctx, uint64(tableSize))
	if err != nil {
		return nil, fmt.Errorf("grow tree-sitter table: %w", err)
	}
	tableBase := align(uint32(tableBaseOut[0]), 1<<meta.tableAlign)
	// Allocate a stack region for the grammar's __stack_pointer. wasi-sdk
	// builds expect a mutable i32 global initialized to the top of an
	// 16-byte-aligned stack region; stack grows downward.
	stackBaseOut, err := w.call(ctx, "calloc", uint64(grammarStackSize+16), 1)
	if err != nil {
		return nil, fmt.Errorf("allocate %s grammar stack: %w", g.Language, err)
	}
	stackBase := align(uint32(stackBaseOut[0]), 16)
	stackTop := stackBase + grammarStackSize
	bridgeName := fmt.Sprintf("g%02d", len(w.languages))
	bridgeBytes := grammarBridgeModule(memBase, tableBase, stackTop)
	if _, err := rt.InstantiateWithConfig(ctx, bridgeBytes, wazero.NewModuleConfig().WithName(bridgeName).WithStartFunctions()); err != nil {
		return nil, fmt.Errorf("instantiate %s grammar import bridge: %w", g.Language, err)
	}
	patched, err := patchGrammarImports(g.WASM, bridgeName)
	if err != nil {
		return nil, fmt.Errorf("patch %s grammar imports: %w", g.Language, err)
	}
	name := "tree-sitter-" + string(g.Language)
	if _, err := rt.InstantiateWithConfig(ctx, patched, wazero.NewModuleConfig().WithName(name).WithStartFunctions()); err != nil {
		return nil, fmt.Errorf("instantiate %s grammar wasm: %w", g.Language, err)
	}
	mod := rt.Module(name)
	if mod == nil {
		return nil, fmt.Errorf("%s grammar module missing", g.Language)
	}
	if fn := mod.ExportedFunction("__wasm_apply_data_relocs"); fn != nil {
		if _, err := fn.Call(ctx); err != nil {
			return nil, fmt.Errorf("%s grammar relocations: %w", g.Language, err)
		}
	}
	if fn := mod.ExportedFunction("__wasm_call_ctors"); fn != nil {
		if _, err := fn.Call(ctx); err != nil {
			return nil, fmt.Errorf("%s grammar constructors: %w", g.Language, err)
		}
	}
	entry := g.EntryName
	if entry == "" {
		entry = string(g.Language)
	}
	ctor := mod.ExportedFunction("tree_sitter_" + entry)
	if ctor == nil {
		return nil, fmt.Errorf("%s grammar constructor missing", g.Language)
	}
	out, err := ctor.Call(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s grammar constructor: %w", g.Language, err)
	}
	ptr := uint32(out[0])
	version, err := w.call(ctx, "ts_language_abi_version", uint64(ptr))
	if err != nil {
		return nil, err
	}
	if version[0] < transferMinVersion || version[0] > transferLanguageVersion {
		return nil, fmt.Errorf("%s grammar ABI %d outside supported range %d..%d", g.Language, version[0], transferMinVersion, transferLanguageVersion)
	}
	lang := &wasmLanguage{
		lang:      g.Language,
		ptr:       ptr,
		version:   int(version[0]),
		symbols:   map[uint32]string{},
		fieldIDs:  map[string]uint32{},
		bridgeMod: rt.Module(bridgeName),
	}
	if err := w.fillLanguageTables(ctx, lang); err != nil {
		return nil, err
	}
	if err := w.initParser(ctx, lang); err != nil {
		return nil, err
	}
	w.languages[g.Language] = lang
	return lang, nil
}

func (w *wasmRuntime) initParser(ctx context.Context, lang *wasmLanguage) error {
	if _, err := w.call(ctx, "ts_parser_new_wasm"); err != nil {
		return err
	}
	parser, okParser := w.mem().ReadUint32Le(w.transfer)
	parserPayload, okPayload := w.mem().ReadUint32Le(w.transfer + sizeOfInt)
	if !okParser || !okPayload || parser == 0 || parserPayload == 0 {
		return fmt.Errorf("tree-sitter parser allocation failed")
	}
	if _, err := w.call(ctx, "ts_parser_set_language", uint64(parser), uint64(lang.ptr)); err != nil {
		return err
	}
	lang.parser = parser
	lang.parserBuf = parserPayload
	return nil
}

func (w *wasmRuntime) fillLanguageTables(ctx context.Context, lang *wasmLanguage) error {
	count, err := w.call(ctx, "ts_language_symbol_count", uint64(lang.ptr))
	if err != nil {
		return err
	}
	for i := uint32(0); i < uint32(count[0]); i++ {
		typ, err := w.call(ctx, "ts_language_symbol_type", uint64(lang.ptr), uint64(i))
		if err != nil {
			return err
		}
		if typ[0] >= 2 {
			continue
		}
		namePtr, err := w.call(ctx, "ts_language_symbol_name", uint64(lang.ptr), uint64(i))
		if err != nil {
			return err
		}
		lang.symbols[i] = w.readCString(uint32(namePtr[0]))
	}
	fields, err := w.call(ctx, "ts_language_field_count", uint64(lang.ptr))
	if err != nil {
		return err
	}
	for i := uint32(1); i <= uint32(fields[0]); i++ {
		namePtr, err := w.call(ctx, "ts_language_field_name_for_id", uint64(lang.ptr), uint64(i))
		if err != nil {
			return err
		}
		if namePtr[0] != 0 {
			lang.fieldIDs[w.readCString(uint32(namePtr[0]))] = i
		}
	}
	return nil
}

func (w *wasmRuntime) parse(ctx context.Context, rt wazero.Runtime, g Grammar, content []byte, filePath string) (Tree, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	lang, err := w.loadLanguage(ctx, rt, g)
	if err != nil {
		return nil, err
	}
	if _, err := w.call(ctx, "ts_parser_reset", uint64(lang.parser)); err != nil {
		return nil, err
	}
	source := string(content)
	utf16Map := utf16ByteMap(source)
	w.currentSource = source
	w.currentUTF16 = utf16Map
	defer func() {
		w.currentSource = ""
		w.currentUTF16 = nil
	}()
	treeOut, err := w.call(ctx, "ts_parser_parse_wasm", uint64(lang.parser), uint64(lang.parserBuf), 0, 0, 0)
	if err != nil {
		return nil, err
	}
	if treeOut[0] == 0 {
		return nil, fmt.Errorf("tree-sitter parse returned null")
	}
	return &wasmTree{rt: w, lang: lang, treePtr: uint32(treeOut[0]), filePath: filePath, content: source, utf16: utf16Map}, nil
}

func utf16ByteMap(s string) []uint32 {
	out := make([]uint32, 0, len(s)+1)
	for byteOffset, r := range s {
		out = append(out, uint32(byteOffset))
		if r > 0xffff {
			out = append(out, uint32(byteOffset))
		}
	}
	out = append(out, uint32(len(s)))
	return out
}

func ExecuteQuery(ctx context.Context, tree Tree, q Query) ([]QueryMatch, error) {
	t, ok := tree.(*wasmTree)
	if !ok {
		return nil, ErrParserAdapterUnavailable
	}
	return t.rt.executeQuery(ctx, t, q)
}

func (w *wasmRuntime) executeQuery(ctx context.Context, tree *wasmTree, q Query) ([]QueryMatch, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	srcLen := len(q.Source)
	srcPtr, err := w.mallocString(ctx, q.Source)
	if err != nil {
		return nil, err
	}
	defer func() { _, _ = w.call(context.Background(), "free", uint64(srcPtr)) }()
	out, err := w.call(ctx, "ts_query_new", uint64(tree.lang.ptr), uint64(srcPtr), uint64(srcLen), uint64(w.transfer), uint64(w.transfer+sizeOfInt))
	if err != nil {
		return nil, err
	}
	queryPtr := uint32(out[0])
	if queryPtr == 0 {
		errByte, _ := w.mem().ReadUint32Le(w.transfer)
		errKind, _ := w.mem().ReadUint32Le(w.transfer + sizeOfInt)
		return nil, fmt.Errorf("tree-sitter query compile failed at byte %d (kind %d)", errByte, errKind)
	}
	defer func() { _, _ = w.call(context.Background(), "ts_query_delete", uint64(queryPtr)) }()
	captureNames, err := w.queryCaptureNames(ctx, queryPtr)
	if err != nil {
		return nil, err
	}
	root := tree.Root().(*wasmNode)
	w.marshalNode(root, w.transfer)
	if _, err := w.call(ctx, "ts_query_matches_wasm", uint64(queryPtr), uint64(tree.treePtr), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, math.MaxUint32, math.MaxUint32); err != nil {
		return nil, err
	}
	rawCount, _ := w.mem().ReadUint32Le(w.transfer)
	startAddr, _ := w.mem().ReadUint32Le(w.transfer + sizeOfInt)
	defer func() {
		if startAddr != 0 {
			_, _ = w.call(context.Background(), "free", uint64(startAddr))
		}
	}()
	var matches []QueryMatch
	addr := startAddr
	for i := uint32(0); i < rawCount; i++ {
		addr += sizeOfInt // pattern index
		captureCount, _ := w.mem().ReadUint32Le(addr)
		addr += sizeOfInt
		captures := map[string]Node{}
		for j := uint32(0); j < captureCount; j++ {
			captureIndex, _ := w.mem().ReadUint32Le(addr)
			addr += sizeOfInt
			node := w.unmarshalNode(tree, addr)
			addr += sizeOfNode
			name := captureNames[captureIndex]
			captures["@"+name] = node
		}
		match := QueryMatch{Captures: captures}
		if queryPredicatesPass(q, match) {
			matches = append(matches, match)
		}
	}
	return matches, nil
}

func queryPredicatesPass(q Query, match QueryMatch) bool {
	for _, p := range q.TextPredicates {
		node, ok := match.Captures[p.Capture]
		text := ""
		if ok && node != nil {
			text = node.Text()
		}
		switch p.Op {
		case "eq?":
			if text != p.Value {
				return false
			}
		case "not-eq?":
			if text == p.Value {
				return false
			}
		case "match?":
			ok, err := regexp.MatchString(p.Value, text)
			if err != nil || !ok {
				return false
			}
		case "not-match?":
			ok, err := regexp.MatchString(p.Value, text)
			if err == nil && ok {
				return false
			}
		}
	}
	return true
}

func (w *wasmRuntime) queryCaptureNames(ctx context.Context, queryPtr uint32) (map[uint32]string, error) {
	out, err := w.call(ctx, "ts_query_capture_count", uint64(queryPtr))
	if err != nil {
		return nil, err
	}
	names := map[uint32]string{}
	for i := uint32(0); i < uint32(out[0]); i++ {
		ptr, err := w.call(ctx, "ts_query_capture_name_for_id", uint64(queryPtr), uint64(i), uint64(w.transfer))
		if err != nil {
			return nil, err
		}
		n, _ := w.mem().ReadUint32Le(w.transfer)
		names[i] = w.readString(uint32(ptr[0]), n)
	}
	return names, nil
}

func (w *wasmRuntime) mallocString(ctx context.Context, s string) (uint32, error) {
	out, err := w.call(ctx, "malloc", uint64(len(s)+1))
	if err != nil {
		return 0, err
	}
	ptr := uint32(out[0])
	if !w.mem().Write(ptr, []byte(s)) || !w.mem().WriteByte(ptr+uint32(len(s)), 0) {
		return 0, fmt.Errorf("write string to wasm memory")
	}
	return ptr, nil
}

func (w *wasmRuntime) callVoid(ctx context.Context, name string) error {
	_, err := w.call(ctx, name)
	return err
}

func (w *wasmRuntime) call(ctx context.Context, name string, args ...uint64) ([]uint64, error) {
	fn := w.core.ExportedFunction(name)
	if fn == nil {
		return nil, fmt.Errorf("tree-sitter export %q missing", name)
	}
	out, err := fn.Call(ctx, args...)
	if err != nil {
		return nil, fmt.Errorf("tree-sitter %s: %w", name, err)
	}
	return out, nil
}

func (w *wasmRuntime) mem() api.Memory { return w.env.Memory() }

func (w *wasmRuntime) readCString(ptr uint32) string {
	if ptr == 0 {
		return ""
	}
	mem := w.mem()
	buf, ok := mem.Read(ptr, mem.Size()-ptr)
	if !ok {
		return ""
	}
	if n := bytes.IndexByte(buf, 0); n >= 0 {
		buf = buf[:n]
	}
	return string(buf)
}

func (w *wasmRuntime) readString(ptr, n uint32) string {
	buf, ok := w.mem().Read(ptr, n)
	if !ok {
		return ""
	}
	return string(buf)
}

func (w *wasmRuntime) marshalNode(n *wasmNode, addr uint32) {
	mem := w.mem()
	_ = mem.WriteUint32Le(addr, n.id)
	_ = mem.WriteUint32Le(addr+4, n.startIndex)
	_ = mem.WriteUint32Le(addr+8, n.startRow)
	_ = mem.WriteUint32Le(addr+12, n.startCol)
	_ = mem.WriteUint32Le(addr+16, n.other)
}

func (w *wasmRuntime) unmarshalNode(tree *wasmTree, addr uint32) *wasmNode {
	id, _ := w.mem().ReadUint32Le(addr)
	if id == 0 {
		return nil
	}
	start, _ := w.mem().ReadUint32Le(addr + 4)
	row, _ := w.mem().ReadUint32Le(addr + 8)
	col, _ := w.mem().ReadUint32Le(addr + 12)
	other, _ := w.mem().ReadUint32Le(addr + 16)
	return &wasmNode{tree: tree, id: id, startIndex: start, startRow: row, startCol: col, other: other}
}

func (t *wasmTree) Language() Language { return t.lang.lang }
func (t *wasmTree) FilePath() string   { return t.filePath }
func (t *wasmTree) Content() string    { return t.content }
func (t *wasmTree) Source() []byte     { return []byte(t.content) }
func (t *wasmTree) RootRange() Range   { return t.Root().Range() }
func (t *wasmTree) byteOffset(utf16Offset uint32) int {
	if int(utf16Offset) >= len(t.utf16) {
		return len(t.content)
	}
	return int(t.utf16[utf16Offset])
}
func (t *wasmTree) Root() Node {
	if _, err := t.rt.call(context.Background(), "ts_tree_root_node_wasm", uint64(t.treePtr)); err != nil {
		return nil
	}
	return t.rt.unmarshalNode(t, t.rt.transfer)
}
func (t *wasmTree) Close() {
	if t.treePtr != 0 {
		_, _ = t.rt.call(context.Background(), "ts_tree_delete", uint64(t.treePtr))
		t.treePtr = 0
	}
}

func (n *wasmNode) Kind() string {
	n.tree.rt.marshalNode(n, n.tree.rt.transfer)
	out, err := n.tree.rt.call(context.Background(), "ts_node_symbol_wasm", uint64(n.tree.treePtr))
	if err != nil {
		return "ERROR"
	}
	if name := n.tree.lang.symbols[uint32(out[0])]; name != "" {
		return name
	}
	return "ERROR"
}

func (n *wasmNode) Range() Range {
	rt := n.tree.rt
	rt.marshalNode(n, rt.transfer)
	endIndexOut, _ := rt.call(context.Background(), "ts_node_end_index_wasm", uint64(n.tree.treePtr))
	rt.marshalNode(n, rt.transfer)
	_, _ = rt.call(context.Background(), "ts_node_end_point_wasm", uint64(n.tree.treePtr))
	endRow, _ := rt.mem().ReadUint32Le(rt.transfer)
	return Range{
		StartByte: n.tree.byteOffset(n.startIndex),
		EndByte:   n.tree.byteOffset(uint32(endIndexOut[0])),
		StartLine: int(n.startRow) + 1,
		EndLine:   int(endRow) + 1,
	}
}

func (n *wasmNode) Text() string {
	rng := n.Range()
	if rng.StartByte < 0 || rng.EndByte > len(n.tree.content) || rng.StartByte > rng.EndByte {
		return ""
	}
	return n.tree.content[rng.StartByte:rng.EndByte]
}

func (n *wasmNode) NamedChildren() []Node {
	rt := n.tree.rt
	rt.marshalNode(n, rt.transfer)
	out, err := rt.call(context.Background(), "ts_node_named_child_count_wasm", uint64(n.tree.treePtr))
	if err != nil {
		return nil
	}
	children := make([]Node, 0, out[0])
	for i := uint32(0); i < uint32(out[0]); i++ {
		rt.marshalNode(n, rt.transfer)
		if _, err := rt.call(context.Background(), "ts_node_named_child_wasm", uint64(n.tree.treePtr), uint64(i)); err != nil {
			return children
		}
		if child := rt.unmarshalNode(n.tree, rt.transfer); child != nil {
			children = append(children, child)
		}
	}
	return children
}

func (n *wasmNode) NamedChildByFieldName(name string) (Node, bool) {
	fieldID, ok := n.tree.lang.fieldIDs[name]
	if !ok {
		return nil, false
	}
	rt := n.tree.rt
	rt.marshalNode(n, rt.transfer)
	if _, err := rt.call(context.Background(), "ts_node_child_by_field_id_wasm", uint64(n.tree.treePtr), uint64(fieldID)); err != nil {
		return nil, false
	}
	child := rt.unmarshalNode(n.tree, rt.transfer)
	return child, child != nil
}

type dylinkMeta struct {
	memorySize  uint32
	memoryAlign uint32
	tableSize   uint32
	tableAlign  uint32
}

func readDylink(wasm []byte) (dylinkMeta, error) {
	if len(wasm) < 12 || string(wasm[:4]) != "\x00asm" {
		return dylinkMeta{}, errors.New("invalid wasm header")
	}
	pos := 8
	if wasm[pos] != 0 {
		return dylinkMeta{}, errors.New("dylink section is not first")
	}
	pos++
	sectionSize, n := readULEB(wasm[pos:])
	if n == 0 {
		return dylinkMeta{}, errors.New("invalid dylink section size")
	}
	pos += n
	end := pos + int(sectionSize)
	name, used, ok := readName(wasm[pos:end])
	if !ok || name != "dylink.0" {
		return dylinkMeta{}, errors.New("missing dylink.0 section")
	}
	pos += used
	for pos < end {
		subtype := wasm[pos]
		pos++
		subSize, n := readULEB(wasm[pos:])
		if n == 0 {
			return dylinkMeta{}, errors.New("invalid dylink subsection")
		}
		pos += n
		subEnd := pos + int(subSize)
		if subtype == 1 {
			memorySize, n1 := readULEB(wasm[pos:subEnd])
			pos += n1
			memoryAlign, n2 := readULEB(wasm[pos:subEnd])
			pos += n2
			tableSize, n3 := readULEB(wasm[pos:subEnd])
			pos += n3
			tableAlign, n4 := readULEB(wasm[pos:subEnd])
			if n1 == 0 || n2 == 0 || n3 == 0 || n4 == 0 {
				return dylinkMeta{}, errors.New("invalid dylink memory info")
			}
			return dylinkMeta{memorySize, memoryAlign, tableSize, tableAlign}, nil
		}
		pos = subEnd
	}
	return dylinkMeta{}, errors.New("dylink memory info not found")
}

func readName(buf []byte) (string, int, bool) {
	n, used := readULEB(buf)
	if used == 0 || used+int(n) > len(buf) {
		return "", 0, false
	}
	return string(buf[used : used+int(n)]), used + int(n), true
}

func readULEB(buf []byte) (uint32, int) {
	var out uint32
	var shift uint
	for i, b := range buf {
		out |= uint32(b&0x7f) << shift
		if b&0x80 == 0 {
			return out, i + 1
		}
		shift += 7
	}
	return 0, 0
}

func writeULEB(buf *bytes.Buffer, v uint32) {
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if v != 0 {
			b |= 0x80
		}
		buf.WriteByte(b)
		if v == 0 {
			return
		}
	}
}

func align(v, by uint32) uint32 {
	if by == 0 {
		return v
	}
	return (v + by - 1) &^ (by - 1)
}

func patchGrammarImports(wasm []byte, bridgeName string) ([]byte, error) {
	if len(wasm) < 8 || string(wasm[:4]) != "\x00asm" {
		return nil, errors.New("invalid wasm header")
	}
	var out bytes.Buffer
	out.Write(wasm[:8])
	pos := 8
	patched := false
	for pos < len(wasm) {
		sectionStart := pos
		id := wasm[pos]
		pos++
		sectionSize, n := readULEB(wasm[pos:])
		if n == 0 {
			return nil, errors.New("invalid wasm section size")
		}
		pos += n
		payloadStart := pos
		payloadEnd := payloadStart + int(sectionSize)
		if payloadEnd > len(wasm) {
			return nil, errors.New("wasm section exceeds input")
		}
		if id != 2 {
			out.Write(wasm[sectionStart:payloadEnd])
			pos = payloadEnd
			continue
		}
		imports, err := rewriteImportSection(wasm[payloadStart:payloadEnd], bridgeName)
		if err != nil {
			return nil, err
		}
		writeSection(&out, 2, imports)
		patched = true
		pos = payloadEnd
	}
	if !patched {
		return nil, errors.New("import section not found")
	}
	return out.Bytes(), nil
}

func rewriteImportSection(payload []byte, bridgeName string) ([]byte, error) {
	count, pos := readULEB(payload)
	if pos == 0 {
		return nil, errors.New("invalid import count")
	}
	type importEntry struct {
		module string
		name   string
		kind   byte
		desc   []byte
	}
	entries := make([]importEntry, 0, count)
	for i := uint32(0); i < count; i++ {
		module, used, ok := readName(payload[pos:])
		if !ok {
			return nil, errors.New("invalid import module name")
		}
		pos += used
		name, used, ok := readName(payload[pos:])
		if !ok {
			return nil, errors.New("invalid import name")
		}
		pos += used
		if pos >= len(payload) {
			return nil, errors.New("missing import kind")
		}
		kind := payload[pos]
		pos++
		descStart := pos
		var err error
		pos, err = skipImportDesc(payload, pos, kind)
		if err != nil {
			return nil, err
		}
		if module == "env" {
			module = grammarImportModule(name, bridgeName)
		}
		entries = append(entries, importEntry{
			module: module,
			name:   name,
			kind:   kind,
			desc:   append([]byte(nil), payload[descStart:pos]...),
		})
	}
	if pos != len(payload) {
		return nil, errors.New("trailing import section bytes")
	}
	var out bytes.Buffer
	writeULEB(&out, uint32(len(entries)))
	for _, entry := range entries {
		writeImport(&out, entry.module, entry.name)
		out.WriteByte(entry.kind)
		out.Write(entry.desc)
	}
	return out.Bytes(), nil
}

func grammarImportModule(name, bridgeName string) string {
	switch name {
	case "malloc", "free", "calloc", "realloc", "memcpy":
		return "tree-sitter-core"
	case "iswspace", "iswalpha", "iswalnum", "iswdigit", "iswlower", "iswupper", "iswxdigit", "towlower", "towupper",
		"abort", "__assert_fail":
		return "deepsec_libc"
	default:
		// __stack_pointer and any other env globals stay routed to
		// the per-grammar bridge module, where the bridge exports a
		// mutable global initialized to the top of an allocated
		// stack region.
		return bridgeName
	}
}

func skipImportDesc(payload []byte, pos int, kind byte) (int, error) {
	switch kind {
	case 0x00: // function type index
		_, n := readULEB(payload[pos:])
		if n == 0 {
			return 0, errors.New("invalid function import descriptor")
		}
		return pos + n, nil
	case 0x01: // table
		if pos >= len(payload) {
			return 0, errors.New("invalid table import descriptor")
		}
		pos++ // element type
		return skipLimits(payload, pos)
	case 0x02: // memory
		return skipLimits(payload, pos)
	case 0x03: // global
		if pos+2 > len(payload) {
			return 0, errors.New("invalid global import descriptor")
		}
		return pos + 2, nil
	default:
		return 0, fmt.Errorf("unsupported import kind %d", kind)
	}
}

func skipLimits(payload []byte, pos int) (int, error) {
	if pos >= len(payload) {
		return 0, errors.New("invalid limits descriptor")
	}
	flags := payload[pos]
	pos++
	_, n := readULEB(payload[pos:])
	if n == 0 {
		return 0, errors.New("invalid limits minimum")
	}
	pos += n
	if flags&0x01 != 0 {
		_, n = readULEB(payload[pos:])
		if n == 0 {
			return 0, errors.New("invalid limits maximum")
		}
		pos += n
	}
	return pos, nil
}

type bridgeFuncImport struct {
	module    string
	name      string
	typeIndex uint32
}

const (
	bridgeTypeI32ToI32 uint32 = iota
	bridgeTypeI32I32ToI32
	bridgeTypeI32I32I32ToI32
	bridgeTypeI32ToVoid
)

var bridgeFuncImports = []bridgeFuncImport{
	{module: "tree-sitter-core", name: "malloc", typeIndex: bridgeTypeI32ToI32},
	{module: "tree-sitter-core", name: "free", typeIndex: bridgeTypeI32ToVoid},
	{module: "tree-sitter-core", name: "calloc", typeIndex: bridgeTypeI32I32ToI32},
	{module: "tree-sitter-core", name: "realloc", typeIndex: bridgeTypeI32I32ToI32},
	{module: "tree-sitter-core", name: "memcpy", typeIndex: bridgeTypeI32I32I32ToI32},
	{module: "deepsec_libc", name: "iswspace", typeIndex: bridgeTypeI32ToI32},
	{module: "deepsec_libc", name: "iswalpha", typeIndex: bridgeTypeI32ToI32},
	{module: "deepsec_libc", name: "iswalnum", typeIndex: bridgeTypeI32ToI32},
	{module: "deepsec_libc", name: "iswdigit", typeIndex: bridgeTypeI32ToI32},
	{module: "deepsec_libc", name: "iswlower", typeIndex: bridgeTypeI32ToI32},
	{module: "deepsec_libc", name: "iswupper", typeIndex: bridgeTypeI32ToI32},
	{module: "deepsec_libc", name: "iswxdigit", typeIndex: bridgeTypeI32ToI32},
	{module: "deepsec_libc", name: "towlower", typeIndex: bridgeTypeI32ToI32},
	{module: "deepsec_libc", name: "towupper", typeIndex: bridgeTypeI32ToI32},
}

func grammarBridgeModule(memoryBase, tableBase, stackTop uint32) []byte {
	var body bytes.Buffer
	body.Write([]byte("\x00asm\x01\x00\x00\x00"))
	writeSection(&body, 1, bridgeTypeSection())
	writeSection(&body, 2, bridgeImportSection())
	writeSection(&body, 6, bridgeGlobalSection(memoryBase, tableBase, stackTop))
	writeSection(&body, 7, bridgeExportSection())
	return body.Bytes()
}

func bridgeTypeSection() []byte {
	var b bytes.Buffer
	writeULEB(&b, 4)
	writeFuncType(&b, []byte{0x7f}, []byte{0x7f})
	writeFuncType(&b, []byte{0x7f, 0x7f}, []byte{0x7f})
	writeFuncType(&b, []byte{0x7f, 0x7f, 0x7f}, []byte{0x7f})
	writeFuncType(&b, []byte{0x7f}, nil)
	return b.Bytes()
}

func bridgeImportSection() []byte {
	var b bytes.Buffer
	writeULEB(&b, uint32(2+len(bridgeFuncImports)))
	writeImport(&b, "env", "memory")
	b.WriteByte(0x02) // memory
	b.WriteByte(0x00) // min only
	writeULEB(&b, 4)
	writeImport(&b, "env", "__indirect_function_table")
	b.WriteByte(0x01) // table
	b.WriteByte(0x70) // funcref
	b.WriteByte(0x00) // min only
	writeULEB(&b, 2)
	for _, fn := range bridgeFuncImports {
		writeImport(&b, fn.module, fn.name)
		b.WriteByte(0x00) // function
		writeULEB(&b, fn.typeIndex)
	}
	return b.Bytes()
}

func bridgeGlobalSection(memoryBase, tableBase, stackTop uint32) []byte {
	var b bytes.Buffer
	writeULEB(&b, 3)
	writeConstGlobal(&b, memoryBase) // index 0: __memory_base (immutable)
	writeConstGlobal(&b, tableBase)  // index 1: __table_base (immutable)
	writeMutableGlobal(&b, stackTop) // index 2: __stack_pointer (mutable)
	return b.Bytes()
}

func bridgeExportSection() []byte {
	var b bytes.Buffer
	writeULEB(&b, uint32(5+len(bridgeFuncImports)))
	writeExport(&b, "memory", 0x02, 0)
	writeExport(&b, "__indirect_function_table", 0x01, 0)
	writeExport(&b, "__memory_base", 0x03, 0)
	writeExport(&b, "__table_base", 0x03, 1)
	writeExport(&b, "__stack_pointer", 0x03, 2)
	for idx, fn := range bridgeFuncImports {
		writeExport(&b, fn.name, 0x00, uint32(idx))
	}
	return b.Bytes()
}

func writeSection(out *bytes.Buffer, id byte, payload []byte) {
	out.WriteByte(id)
	writeULEB(out, uint32(len(payload)))
	out.Write(payload)
}

func writeImport(b *bytes.Buffer, module, name string) {
	writeNameBytes(b, module)
	writeNameBytes(b, name)
}

func writeExport(b *bytes.Buffer, name string, kind byte, idx uint32) {
	writeNameBytes(b, name)
	b.WriteByte(kind)
	writeULEB(b, idx)
}

func writeNameBytes(b *bytes.Buffer, name string) {
	writeULEB(b, uint32(len(name)))
	b.WriteString(name)
}

func writeFuncType(b *bytes.Buffer, params, results []byte) {
	b.WriteByte(0x60)
	writeULEB(b, uint32(len(params)))
	b.Write(params)
	writeULEB(b, uint32(len(results)))
	b.Write(results)
}

func writeConstGlobal(b *bytes.Buffer, value uint32) {
	b.WriteByte(0x7f) // i32
	b.WriteByte(0x00) // immutable
	b.WriteByte(0x41) // i32.const
	writeSLEB32(b, int32(value))
	b.WriteByte(0x0b)
}

func writeMutableGlobal(b *bytes.Buffer, value uint32) {
	b.WriteByte(0x7f) // i32
	b.WriteByte(0x01) // mutable
	b.WriteByte(0x41) // i32.const
	writeSLEB32(b, int32(value))
	b.WriteByte(0x0b)
}

func writeSLEB32(buf *bytes.Buffer, v int32) {
	for {
		b := byte(v & 0x7f)
		v >>= 7
		done := (v == 0 && b&0x40 == 0) || (v == -1 && b&0x40 != 0)
		if !done {
			b |= 0x80
		}
		buf.WriteByte(b)
		if done {
			return
		}
	}
}
