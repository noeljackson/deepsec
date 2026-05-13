#!/usr/bin/env bash
# scripts/build-grammar-wasm.sh — produce tree-sitter-<lang>.wasm from a
# raw npm tree-sitter-<lang> package.
#
# Most tree-sitter grammar packages on npm ship pre-built WASM
# (`tree-sitter-go@0.25.0`, `tree-sitter-typescript@0.23.2`,
# `tree-sitter-python@0.25.0`, `tree-sitter-rust@0.24.0`,
# `tree-sitter-java@0.23.5`). Some do not: `tree-sitter-kotlin`,
# `tree-sitter-swift`, `tree-sitter-c`, `tree-sitter-cpp` ship C
# sources only and require emscripten to compile.
#
# This script wraps `tree-sitter build --wasm` inside the official
# `emscripten/emsdk` docker image so contributors don't need to
# install emscripten + the tree-sitter CLI locally. Output lands at
# `internal/scanner/ast/grammars/tree-sitter-<lang>.wasm`.
#
# Usage:
#   scripts/build-grammar-wasm.sh kotlin tree-sitter-kotlin@0.3.8
#   scripts/build-grammar-wasm.sh swift  tree-sitter-swift@0.7.1
#   scripts/build-grammar-wasm.sh c      tree-sitter-c@0.24.1
#   scripts/build-grammar-wasm.sh cpp    tree-sitter-cpp@0.23.4

set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <lang-key> <npm-package-spec>"
  echo "  lang-key is the suffix used by grammars/<lang-key>.wasm"
  echo "  npm-package-spec is the form 'tree-sitter-<name>@<version>'"
  exit 2
fi

LANG_KEY="$1"
PKG_SPEC="$2"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="$REPO_ROOT/internal/scanner/ast/grammars"
OUT_WASM="$OUT_DIR/tree-sitter-$LANG_KEY.wasm"

mkdir -p "$OUT_DIR"

WORK="$(mktemp -d -t deepsec-tsbuild.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

echo "==> staging package $PKG_SPEC in $WORK"
cd "$WORK"
npm pack "$PKG_SPEC" >/dev/null

# tarball name e.g. tree-sitter-kotlin-0.3.8.tgz; extract → ./package/
TARBALL="$(ls tree-sitter-*.tgz | head -1)"
mkdir -p package
tar -xzf "$TARBALL" -C . --strip-components=1 || tar -xzf "$TARBALL"

echo "==> running tree-sitter build --wasm via emscripten/emsdk docker image"
docker run --rm \
  -u "$(id -u):$(id -g)" \
  -v "$WORK":/work \
  -w /work \
  emscripten/emsdk:latest \
  bash -lc '
    set -euo pipefail
    npm install --no-save --silent tree-sitter-cli@latest
    npx tree-sitter build --wasm .
  '

# The output WASM is named tree-sitter-<name>.wasm by the CLI.
BUILT="$(ls tree-sitter-*.wasm | head -1)"
if [ -z "$BUILT" ]; then
  echo "ERROR: tree-sitter build did not produce a WASM file" >&2
  exit 1
fi
cp "$BUILT" "$OUT_WASM"

echo "==> wrote $OUT_WASM ($(du -h "$OUT_WASM" | cut -f1))"
echo
echo "Next steps:"
echo "  1. Add the language to internal/scanner/ast/language.go"
echo "  2. Add an embed line + DefaultGrammars entry in"
echo "     internal/scanner/ast/grammars.go"
echo "  3. Check whether the grammar needs new libc imports in"
echo "     internal/scanner/ast/wazero_abi.go — run the ParseQuery"
echo "     test for the language; missing-import errors print the"
echo "     unsatisfied symbol name."
echo "  4. Add parser + query tests in"
echo "     internal/scanner/ast/runtime_test.go"
