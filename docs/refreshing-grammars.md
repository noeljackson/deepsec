# Refreshing tree-sitter grammars

deepsec embeds tree-sitter WASM binaries under
`internal/scanner/ast/grammars/`. The bridge in
`internal/scanner/ast/wazero_abi.go` loads them at runtime via wazero.

**Every grammar is built locally from its upstream npm
`tree-sitter-<lang>` package, in a pinned `emscripten/emsdk` docker
image, with a pinned `tree-sitter-cli` version.** The resulting WASMs
are wasi-sdk-style: dynamic-link with a `dylink.0` section, env
imports for memory + table + a small libc surface + a mutable
`__stack_pointer` global. No pre-built WASMs from npm are accepted —
reproducibility requires we own the build.

## Build a grammar

```bash
scripts/build-grammar-wasm.sh <lang-key> <npm-package-spec> [subdir]
```

| lang-key   | spec                                  | subdir       |
|------------|---------------------------------------|--------------|
| go         | `tree-sitter-go@0.25.0`               |              |
| python     | `tree-sitter-python@0.25.0`           |              |
| typescript | `tree-sitter-typescript@0.23.2`       | `typescript` |
| tsx        | `tree-sitter-typescript@0.23.2`       | `tsx`        |
| rust       | `tree-sitter-rust@0.24.0`             |              |
| java       | `tree-sitter-java@0.23.5`             |              |
| kotlin     | `tree-sitter-kotlin@0.3.8`            |              |
| swift      | `tree-sitter-swift@0.7.1`             |              |
| c          | `tree-sitter-c@0.24.1`                |              |
| cpp        | `tree-sitter-cpp@0.23.4`              |              |

The script does:

1. Mounts a build dir under `$REPO/.cache/grammar-build/` (gitignored;
   uses repo-local path so noexec-mounted `/tmp` doesn't trip npm's
   node-gyp-build postinstall step).
2. Spawns the pinned `emscripten/emsdk` docker image with that dir
   mounted at `/work`.
3. Inside the container: `npm pack` the grammar, extract,
   `npm install tree-sitter-cli@<pinned>`, run
   `tree-sitter build --wasm`.
4. `chown`s the resulting WASM back to the host user.
5. Copies the WASM to `internal/scanner/ast/grammars/`.

Then re-run `go test ./internal/scanner/ast/...` to confirm.

## Refreshing all grammars

```bash
rm internal/scanner/ast/grammars/tree-sitter-*.wasm

for triple in \
  "go::tree-sitter-go@0.25.0" \
  "python::tree-sitter-python@0.25.0" \
  "typescript:typescript:tree-sitter-typescript@0.23.2" \
  "tsx:tsx:tree-sitter-typescript@0.23.2" \
  "rust::tree-sitter-rust@0.24.0" \
  "java::tree-sitter-java@0.23.5" \
  "kotlin::tree-sitter-kotlin@0.3.8" \
  "swift::tree-sitter-swift@0.7.1" \
  "c::tree-sitter-c@0.24.1" \
  "cpp::tree-sitter-cpp@0.23.4"
do
  lang="${triple%%:*}"; rest="${triple#*:}"
  subdir="${rest%%:*}"; spec="${rest#*:}"
  scripts/build-grammar-wasm.sh "$lang" "$spec" "${subdir:-.}"
done
```

## Bumping the toolchain

The script pins two things at the top:

- `TS_CLI_VERSION` — the tree-sitter-cli version.
- `EMSDK_IMAGE` — the emscripten/emsdk image, by content digest.

To bump:

```bash
# tree-sitter-cli version (inspected inside docker so we don't need
# npm on the host):
docker run --rm emscripten/emsdk:<tag> bash -lc 'npm view tree-sitter-cli version'

# emscripten/emsdk digest:
docker pull emscripten/emsdk:<tag>
docker inspect emscripten/emsdk:<tag> --format='{{.RepoDigests}}'
```

Bumping either is a substantive change — rebuild every grammar and
review the WASM diff in the PR. WASMs are checked in as binary, so
reviewers will see size changes and the embed diff in `git log -p`.

## Bridge surface

Each grammar imports from the `env` module:

- `memory` (shared with tree-sitter-core)
- `__indirect_function_table`
- `__memory_base` (immutable i32 global)
- `__table_base` (immutable i32 global)
- `__stack_pointer` (mutable i32 global, initialised to the top of an
  allocated stack region — 256 KiB per grammar)
- A small libc surface: `malloc`, `free`, `calloc`, `realloc`,
  `memcpy`, `iswspace`, `iswalpha`, `iswalnum`, `iswdigit`, `iswlower`,
  `iswupper`, `iswxdigit`, `towlower`, `towupper`, `abort`,
  `__assert_fail`.

The bridge in `internal/scanner/ast/wazero_abi.go` routes:

- `malloc`/`free`/`calloc`/`realloc`/`memcpy` → tree-sitter-core
  (shared allocator)
- `isw*`/`tow*`/`abort`/`__assert_fail` → `deepsec_libc` host module
- `__memory_base`/`__table_base`/`__stack_pointer` → a per-grammar
  bridge module that exports those globals at the addresses returned
  from a fresh `calloc()` call against tree-sitter-core's heap.

If a new grammar version starts importing a symbol the bridge doesn't
know about, the test suite fails immediately with a clear
"unsatisfied import" error naming the symbol. Add the new symbol to
`bridgeFuncImports` + `grammarImportModule` + the libc host (with a
sensible stub) and re-run.
