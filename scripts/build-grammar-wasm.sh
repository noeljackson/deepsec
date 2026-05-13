#!/usr/bin/env bash
# scripts/build-grammar-wasm.sh — compile a tree-sitter grammar npm
# package to WASM. Everything `npm`-flavoured runs inside a pinned
# emscripten/emsdk docker image; the host doesn't touch the npm
# registry, doesn't install global tools, and doesn't need node.
#
# Usage:
#   scripts/build-grammar-wasm.sh kotlin tree-sitter-kotlin@0.3.8
#   scripts/build-grammar-wasm.sh swift  tree-sitter-swift@0.7.1
#   scripts/build-grammar-wasm.sh c      tree-sitter-c@0.24.1
#   scripts/build-grammar-wasm.sh cpp    tree-sitter-cpp@0.23.4
#
# Output: internal/scanner/ast/grammars/tree-sitter-<lang-key>.wasm
#
# Reproducibility: tree-sitter-cli version + tarball integrity hash and
# the emsdk image digest are pinned below. Bump deliberately.

set -euo pipefail

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
  echo "usage: $0 <lang-key> <npm-package-spec> [subdir]"
  echo "  lang-key is the suffix used by grammars/<lang-key>.wasm"
  echo "  npm-package-spec is the form 'tree-sitter-<name>@<version>'"
  echo "  subdir is the subdirectory containing grammar.js (e.g. 'typescript'"
  echo "    or 'tsx' inside the tree-sitter-typescript package). Default is '.'."
  exit 2
fi

LANG_KEY="$1"
PKG_SPEC="$2"
SUBDIR="${3:-.}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="$REPO_ROOT/internal/scanner/ast/grammars"
OUT_WASM="$OUT_DIR/tree-sitter-$LANG_KEY.wasm"

mkdir -p "$OUT_DIR"

# Build inside the repo's `.cache/grammar-build` rather than $TMPDIR
# because some hosts mount /tmp with noexec, which trips npm's
# node-gyp-build postinstall step for the tree-sitter-cli dependency.
SCRATCH_PARENT="$REPO_ROOT/.cache/grammar-build"
mkdir -p "$SCRATCH_PARENT"
WORK="$(mktemp -d "$SCRATCH_PARENT/build.XXXXXX")"

# tree-sitter-cli version pin. npm validates registry tarball integrity
# on install (sha512 in the .tgz attestation). Bump deliberately.
TS_CLI_VERSION="0.26.8"

# emscripten/emsdk image pinned by content digest. Refresh with:
#   docker pull emscripten/emsdk:4.0.4
#   docker inspect emscripten/emsdk:4.0.4 --format='{{.RepoDigests}}'
EMSDK_IMAGE="emscripten/emsdk@sha256:4e332f7343b6f66320bf72f7ecc01a3d9f3866721a13b0e5c7b96505d6ab148a"

UID_HOST="$(id -u)"
GID_HOST="$(id -g)"

# Cleanup runs inside docker (root) because node_modules contains files
# created with root ownership during npm install; the host user can't
# rm them.
cleanup() {
  if [ -d "$WORK" ]; then
    docker run --rm -v "$WORK":/work --entrypoint /bin/sh "$EMSDK_IMAGE" \
      -c 'rm -rf /work/*' 2>/dev/null || true
    rmdir "$WORK" 2>/dev/null || rm -rf "$WORK" 2>/dev/null || true
  fi
}
trap cleanup EXIT

echo "==> running tree-sitter build --wasm inside emscripten container"
# Everything npm-related happens inside docker: npm pack, tar, npm
# install, npx tree-sitter, the build. The host never invokes npm.
docker run --rm \
  -v "$WORK":/work \
  -w /work \
  -e "PKG_SPEC=$PKG_SPEC" \
  -e "SUBDIR=$SUBDIR" \
  -e "TS_CLI_VERSION=$TS_CLI_VERSION" \
  -e "UID_HOST=$UID_HOST" \
  -e "GID_HOST=$GID_HOST" \
  "$EMSDK_IMAGE" \
  bash -lc '
    set -euo pipefail
    echo "==> staging $PKG_SPEC"
    npm pack --silent "$PKG_SPEC" >/dev/null
    tarball=$(ls tree-sitter-*.tgz | head -1)
    tar -xzf "$tarball" --strip-components=1
    rm "$tarball"

    echo "==> installing tree-sitter-cli@$TS_CLI_VERSION"
    # --silent suppresses progress; npm itself verifies registry sha512
    # for each fetched tarball. The grammar package.json may declare an
    # older tree-sitter-cli devDep; we explicitly install the pinned
    # version, which prints an `invalid` warning from npm ls but is
    # exactly what we want.
    npm install --no-save --silent --no-audit --no-fund \
      "tree-sitter-cli@$TS_CLI_VERSION" >/dev/null 2>&1

    echo "==> building wasm (subdir=$SUBDIR)"
    if [ "$SUBDIR" = "." ]; then
      npx tree-sitter build --wasm .
    else
      # Multi-grammar packages (e.g. tree-sitter-typescript ships
      # typescript/ and tsx/ subdirs). Build from inside the subdir so
      # the CLI picks up the correct grammar.json. tree-sitter may
      # build sibling grammars too — only copy the one matching the
      # subdir we asked for, to keep the output unambiguous.
      (cd "$SUBDIR" && npx tree-sitter build --wasm .)
      target_wasm="$SUBDIR/tree-sitter-$SUBDIR.wasm"
      if [ ! -f "$target_wasm" ]; then
        echo "ERROR: expected $target_wasm, found:" >&2
        ls "$SUBDIR"/*.wasm 2>&1 >&2
        exit 1
      fi
      # Clear /work of any leftover wasm before the host-side copy.
      rm -f /work/tree-sitter-*.wasm
      cp "$target_wasm" /work/
    fi

    chown "$UID_HOST:$GID_HOST" tree-sitter-*.wasm
  '

# The output WASM is named tree-sitter-<name>.wasm by the CLI.
BUILT="$(ls "$WORK"/tree-sitter-*.wasm | head -1)"
if [ -z "$BUILT" ]; then
  echo "ERROR: tree-sitter build did not produce a WASM file" >&2
  exit 1
fi
cp "$BUILT" "$OUT_WASM"

echo "==> wrote $OUT_WASM ($(du -h "$OUT_WASM" | cut -f1))"
