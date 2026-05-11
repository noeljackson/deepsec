# CLAUDE.md

Pointer file for Claude Code working in this repo. User-facing docs are
in [README.md](./README.md); contributor docs in
[CONTRIBUTING.md](./CONTRIBUTING.md). Read those first.

## Repo shape

This is a Rust workspace.

```
crates/
  deepsec-core/        Types, paths, schemas, JSON persistence
  deepsec-scanner/     File walking, tech detection, TOML matcher engine
  deepsec-processor/   AI pipeline (AgentBackend trait + HTTP backends)
  deepsec-cli/         The `deepsec` binary
fixtures/vulnerable-app/  Planted-vulnerability fixture used by tests
docs/                  User-facing docs
```

## Commands

```bash
cargo build --release          # build the binary at target/release/deepsec
cargo test --workspace         # unit + integration tests
cargo test -p deepsec-cli --test cli  # E2E tests against the fixture
cargo clippy --workspace       # lint
```

## Patterns to keep in mind

- Matchers are declarative TOML, embedded into the binary via
  `include_str!` from `crates/deepsec-scanner/matchers/*.toml`. User-defined
  matchers go in separate TOML files referenced from `[matchers].extra_paths`.
- The wire format on disk (`data/<projectId>/files/*.json`,
  `runs/*.json`) matches the original TS implementation. Don't break
  `serde` field renames in `deepsec-core/src/types.rs` without thought.
- Agent backends live in `crates/deepsec-processor/src/agents/`. Adding
  one is implementing the `AgentBackend` async trait.
- Path-safety: every disk write goes through `assert_safe_segment` /
  `assert_safe_file_path` in `deepsec-core/src/paths.rs`. Do not bypass.
- Concurrency: `process` uses `tokio::sync::Semaphore` +
  `FuturesUnordered`. Quota exhaustion sets a shared `AtomicBool` so
  in-flight batches abort cleanly.
