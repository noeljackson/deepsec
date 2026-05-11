# Rust rewrite — migration guide

The Rust implementation lives in `crates/` and produces a single
binary `deepsec`. The legacy TypeScript implementation in `packages/`
is preserved for reference; it should be removed once the Rust port
reaches feature parity with whatever workflow you depend on.

## Quick start

```bash
cargo build --release
./target/release/deepsec init --project-id myproj --root .
./target/release/deepsec list-matchers
./target/release/deepsec scan --project-id myproj
ANTHROPIC_API_KEY=... ./target/release/deepsec process --project-id myproj
./target/release/deepsec report --project-id myproj
```

## Workspace shape

| Crate                 | Replaces TS package          | Purpose |
|-----------------------|------------------------------|---------|
| `deepsec-core`        | `@deepsec/core`              | Types, schemas, paths, JSON persistence |
| `deepsec-scanner`     | `@deepsec/scanner`           | File walking, tech detection, matcher engine |
| `deepsec-processor`   | `@deepsec/processor`         | AI enrichment pipeline; multi-backend |
| `deepsec-cli` (`deepsec`) | `deepsec` CLI            | Commands: scan, process, revalidate, triage, report, … |

## What changed

### Config — TOML instead of TypeScript

`deepsec.config.ts` becomes `deepsec.config.toml`. There is no
TypeScript loader and no runtime plugin system; user-defined matchers
are TOML files referenced from `matchers.extra_paths`.

```toml
default_agent = "anthropic"

[matchers]
extra_paths = ["./my-matchers/internal.toml"]

[[projects]]
id = "webapp"
root = "./apps/webapp"
github_url = "https://github.com/acme/webapp/blob/main"
info_markdown = """
Project-specific context surfaced to the AI agent.
"""
prompt_append = "Pay extra attention to /api/admin/*."
priority_paths = ["src/api/admin/", "src/lib/auth/"]
```

### Matchers — TOML

Matchers no longer ship as `.ts` modules. They're TOML records:

```toml
[[matcher]]
slug = "my-matcher"
description = "..."
noise_tier = "normal"          # "precise" | "normal" | "noisy"
file_patterns = ["**/*.ts", "**/*.tsx"]
patterns = ["(?i)\\bDEBUG\\s*=\\s*True\\b"]
suppress_patterns = []          # if any matches the snippet window, drop the hit
require_content = []            # ALL must match somewhere in the file or matcher is a no-op
exclude_path_patterns = []      # path regexes to skip
snippet_before = 1
snippet_after = 5
label = "human-readable matched pattern label"

[matcher.requires]              # optional gate
tech = ["nextjs"]                # OR semantics with sentinel_files
sentinel_files = []
sentinel_contains = []
```

A bundled pack (`crates/deepsec-scanner/matchers/*.toml`) ships embedded
in the binary. Cover categories include:

- `core.toml` — auth-bypass, SQL injection, command injection, SSRF,
  path traversal, open redirect, dangerous-html, CORS wildcard, debug
  endpoint, dev-auth-bypass, env exposure, error message leak.
- `secrets.toml` — plaintext secret literals, secrets logged, weak
  default secrets.
- `crypto.toml` — insecure crypto primitives, JWT algorithm confusion,
  non-CSPRNG for security values.
- `nextjs.toml`, `express.toml`, `python.toml`, `rails.toml`, `go.toml`,
  `rust.toml` — framework entry points.
- `infra.toml` — Dockerfile, Terraform IAM wildcards, GitHub Actions
  pull_request_target, K8s privileged pods.
- `ai.toml` — agent loops without caps, untrusted prompt input, MCP
  tool handlers.

Run `deepsec list-matchers` to see the full set.

The original TS implementation shipped ~200 matchers, many with
hand-written walker logic. This pack is intentionally smaller and
declarative — high-precision matchers translated faithfully, noisy
matchers omitted. The intent is that organizations contribute the
specific matchers they care about as additional TOML files.

### Agent backends — HTTP, not SDKs

Instead of bundling `@anthropic-ai/claude-agent-sdk` and
`@openai/codex-sdk`, the Rust processor speaks HTTP directly via
`reqwest`. Two backends ship:

- `anthropic` — POST to `/v1/messages` (Anthropic Messages API).
  Default model: `claude-sonnet-4-6`. Env: `ANTHROPIC_API_KEY`,
  optional `ANTHROPIC_BASE_URL`.
- `openai` — POST to `/v1/chat/completions` with `response_format:
  json_object`. Default model: `gpt-4.1-mini`. Env: `OPENAI_API_KEY`,
  optional `OPENAI_BASE_URL`. Compatible with Azure OpenAI, OpenRouter,
  vLLM, etc. via `OPENAI_BASE_URL`.

Adding a third backend means implementing the `AgentBackend` async
trait (`crates/deepsec-processor/src/agents/mod.rs`). The trait has
three methods: `investigate`, `revalidate`, `triage`.

### On-disk format

Wire-compatible with the TS implementation. `data/<projectId>/`
contains `project.json`, `tech.json`, `files/...json`, `runs/...json`,
`reports/...`. A repo's data directory written by the TS deepsec can be
read by the Rust deepsec and vice versa — same field names, same casing.

### Sandbox subsystem

The Vercel-Sandbox orchestrator (`packages/deepsec/src/sandbox/`) has
no Rust analogue. If you need fan-out across machines, run the Rust
`deepsec` binary inside whatever orchestrator you already use.

## CLI command mapping

| TS                                   | Rust                              |
|--------------------------------------|-----------------------------------|
| `deepsec init`                        | `deepsec init`                     |
| `deepsec init-project`                | `deepsec init-project`             |
| `deepsec scan`                        | `deepsec scan` (+ `--diff`, `--files`, `--files-from`) |
| `deepsec process`                     | `deepsec process` (+ `--concurrency`, `--diff`, `--reinvestigate`) |
| `deepsec revalidate`                  | `deepsec revalidate`               |
| `deepsec triage`                      | `deepsec triage`                   |
| `deepsec enrich`                      | `deepsec enrich`                   |
| `deepsec status`                      | `deepsec status`                   |
| `deepsec report`                      | `deepsec report`                   |
| `deepsec metrics`                     | `deepsec metrics`                  |
| `deepsec export`                      | `deepsec export`                   |
| `deepsec pr-comment` (helper)         | `deepsec pr-comment`               |
| `deepsec data-commit` (helper)        | `deepsec data-commit`              |
| `deepsec preflight` (helper)          | `deepsec preflight`                |
| `deepsec sandbox-*`                   | dropped (Vercel-specific)          |

## Known gaps vs. TS

These remaining gaps are intentional architecture choices, not pending
work:

- **JS plugin loader**: dropped on purpose. Custom matchers are TOML
  via `[matchers].extra_paths`; custom notifiers / ownership providers
  are out of scope for the binary and should be implemented as
  downstream wrappers around `deepsec export`.
- **Vercel-Sandbox orchestrator**: dropped. Wrap `deepsec` in
  whatever fan-out you already use (GitHub Actions matrix, Kubernetes
  Jobs, Buildkite parallel groups, etc.).
- **Bundled matcher count**: 82 in Rust vs ~200 in TS. The dropped
  matchers were narrow framework-specific helpers; add them yourself
  via `extra_paths` or contribute upstream.
