# Refreshing tree-sitter grammars

deepsec embeds tree-sitter WASM binaries under
`internal/scanner/ast/grammars/`. The bridge in
`internal/scanner/ast/wazero_abi.go` loads them at runtime via wazero.

When a grammar needs to move forward — e.g. a new tree-sitter release
adds nodes deepsec wants to match — the WASM has to be regenerated.
There are two flavours of upstream package:

## A) Pre-built WASM already on npm

Most grammars deepsec uses ship a `.wasm` inside the npm tarball:

| Language    | Package                          | Current |
|-------------|----------------------------------|---------|
| Go          | `tree-sitter-go`                 | 0.25.0  |
| Python      | `tree-sitter-python`             | 0.25.0  |
| TypeScript  | `tree-sitter-typescript`         | 0.23.2  |
| Rust        | `tree-sitter-rust`               | 0.24.0  |
| Java        | `tree-sitter-java`               | 0.23.5  |

To refresh one of these:

```bash
cd /tmp && rm -rf refresh && mkdir refresh && cd refresh
npm pack tree-sitter-rust@0.24.1
tar -xzf tree-sitter-rust-0.24.1.tgz package/tree-sitter-rust.wasm
cp package/tree-sitter-rust.wasm \
   $REPO/internal/scanner/ast/grammars/tree-sitter-rust.wasm

# Bump the version comment + Version field in grammars.go
$EDITOR $REPO/internal/scanner/ast/grammars.go

# Run the tests to confirm the new build parses and ABI is compatible
go test ./internal/scanner/ast/...
```

If the ABI version changes (transferMinVersion / transferLanguageVersion
in `wazero_abi.go`), the test will fail with
`unexpected tree-sitter ABI range`. Bump those constants and retest.

If new libc imports are required (the grammar uses `iswspace`,
`malloc`, etc. that the bridge doesn't yet provide), the test will
fail at load time with an unsatisfied import. Add the shim in
`instantiateLibcHost` and `grammarImportModule` in `wazero_abi.go`.

## B) Source-only npm packages — need emscripten

Some grammars publish only C source on npm and require local
compilation: `tree-sitter-kotlin`, `tree-sitter-swift`,
`tree-sitter-c`, `tree-sitter-cpp`. For those, use the wrapper script:

```bash
scripts/build-grammar-wasm.sh kotlin tree-sitter-kotlin@0.3.8
scripts/build-grammar-wasm.sh swift  tree-sitter-swift@0.7.1
scripts/build-grammar-wasm.sh c      tree-sitter-c@0.24.1
scripts/build-grammar-wasm.sh cpp    tree-sitter-cpp@0.23.4
```

This:

1. Pulls the npm package into a temp dir.
2. Runs `tree-sitter build --wasm` inside the official
   `emscripten/emsdk` docker image (so contributors don't need to
   install emscripten and the tree-sitter CLI locally).
3. Copies the produced `tree-sitter-<lang>.wasm` to
   `internal/scanner/ast/grammars/`.

The first run pulls a ~600 MB docker image. Subsequent runs are fast.

After the WASM is in place, add the language to
`internal/scanner/ast/language.go`, embed it in `grammars.go`,
check for new libc imports as above, and add parser + query tests in
`runtime_test.go`. See the comments in `grammars.go` for the layout
existing entries use.

## CI vs local

Builds happen locally and the resulting WASM is checked in. CI does
not regenerate WASMs — they're treated as committed artefacts so the
build is reproducible without docker / emscripten in the CI image.

This trade-off is intentional: grammar refreshes are infrequent and
require human review (the test suite catches obvious regressions but
not behaviour shifts). Auto-refresh in CI would surface drift the
maintainer hasn't reviewed.
