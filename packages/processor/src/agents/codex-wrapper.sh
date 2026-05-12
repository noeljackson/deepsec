#!/bin/sh
# Wrapper around the codex CLI that tees stderr to a known log file so the
# parent JS process can inspect it after exit.
#
# WHY: @openai/codex-sdk's CodexExec captures stderr into a buffer and only
# surfaces it when the child exits non-zero. We're seeing many silent
# failures — codex exits cleanly with empty turns, no error event, no
# stderr surfaced. Routing stderr to disk via a wrapper lets us read what
# codex actually said about the failure (rate-limit responses, auth
# errors, etc.) regardless of exit code.
#
# Env in:
#   CODEX_REAL_BIN    absolute path to the real codex bin script (required)
#   CODEX_STDERR_LOG  path to write stderr to (required)
#
# We exec the real binary with stderr redirected. The shebang on the real
# bin handles its own dispatch (Node-resolves the platform Rust binary).
set -e
: "${CODEX_REAL_BIN:?CODEX_REAL_BIN must be set}"
: "${CODEX_STDERR_LOG:?CODEX_STDERR_LOG must be set}"
exec "$CODEX_REAL_BIN" "$@" 2>"$CODEX_STDERR_LOG"
