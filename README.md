# deepsec

`deepsec` is an agent-powered vulnerability scanner that you can run in your
own infrastructure, optimized to perform on-demand review of code in existing
large-scale repos.

A regex-driven scanner produces high-recall *candidate* matches; a configurable
AI backend then investigates each candidate against the actual source code and
emits real findings — severity, confidence, recommendation, and revalidatable
verdicts on each one.

> **Note.** This is the Rust rewrite. It supersedes the original TypeScript
> implementation. See [`MIGRATION.md`](./MIGRATION.md) if you need a mapping
> from the old commands.

## Install

```bash
git clone https://github.com/noeljackson/deepsec
cd deepsec
cargo install --path crates/deepsec-cli
```

This builds a single `deepsec` binary into `~/.cargo/bin/`. The bundled
matcher pack is embedded into the binary at compile time.

## Quick start

```bash
# in the repo you want to scan
deepsec init --project-id myproj --root .

# run the regex scanner
deepsec scan --project-id myproj

# investigate the candidates with an AI backend
export ANTHROPIC_API_KEY=sk-ant-...
deepsec process --project-id myproj --agent anthropic --concurrency 4

# render a human-readable report
deepsec report --project-id myproj
```

## Backends

`deepsec` speaks HTTP directly to the model provider — no Node SDK
dependency. Two backends ship in the binary:

| Backend     | `--agent`     | Env vars                                | Default model       |
|-------------|---------------|-----------------------------------------|---------------------|
| Anthropic   | `anthropic`   | `ANTHROPIC_API_KEY`, `ANTHROPIC_BASE_URL` | `claude-sonnet-4-6` |
| OpenAI      | `openai`      | `OPENAI_API_KEY`, `OPENAI_BASE_URL`     | `gpt-4.1-mini`      |

`OPENAI_BASE_URL` lets you point at Azure OpenAI, OpenRouter, vLLM, or
any OpenAI-compatible gateway. Adding a third backend = one `impl
AgentBackend` (see `crates/deepsec-processor/src/agents/`).

## Workflow

```text
       ┌──────────────────────────────────────────────┐
       │                                              │
       │  scan (regex)  →  candidates  ─┐             │
       │                                ▼             │
       │                process (AI)  →  findings  ──┐│
       │                                              ▼│
       │                          revalidate / triage  │
       │                                              │ │
       │                              report / export │ │
       │                                              ▼ │
       └──────────────────────────────────────────────┘
```

| Stage       | What it does                                                  |
|-------------|---------------------------------------------------------------|
| `scan`      | Walk files, run regex matchers gated on detected tech, write `FileRecord` JSON. |
| `process`   | Batch FileRecords by directory, ask the AI backend to confirm or reject candidates. |
| `revalidate`| Re-check existing findings against the *current* source: TP / FP / fixed / uncertain. |
| `triage`    | Assign priority (P0/P1/P2/skip), exploitability, impact.       |
| `enrich`    | Populate `gitInfo.recentCommitters` via `git log`.             |
| `report`    | Markdown + JSON + CSV per project.                             |
| `export`    | Filtered JSON dump for downstream pipelines.                   |
| `pr-comment`| Markdown for net-new findings from a specific run.             |
| `data-commit` | `git add data/ && git commit` to version your scan results.  |
| `metrics`   | Aggregate cost, tokens, TP/FP rates across runs.               |

Run `deepsec --help` for the full command list, `deepsec <cmd> --help` for
flags on a specific command.

## CI / pull-request workflow

```bash
deepsec scan --project-id myproj --diff origin/main
deepsec process --project-id myproj --diff origin/main --concurrency 8
deepsec pr-comment --project-id myproj --output pr-comment.md --skip-empty
```

The `--diff <ref>` flag shells out to `git diff --name-only --diff-filter=ACMR
<ref>` and bounds the work to changed files. `pr-comment` filters to findings
whose `producedByRunId` matches the most recent process run.

## Configuration

`deepsec.config.toml` (auto-discovered upward from cwd):

```toml
default_agent = "anthropic"

[matchers]
# only   = []    # whitelist of matcher slugs
# exclude = []   # blacklist
extra_paths = ["./my-matchers/internal.toml"]

[[projects]]
id = "webapp"
root = "./apps/webapp"
github_url = "https://github.com/acme/webapp/blob/main"
info_markdown = """
This service handles payments. Pay extra attention to anything under /api/payments.
"""
prompt_append = "When in doubt about authentication boundaries, flag it."
priority_paths = ["src/api/admin/", "src/lib/auth/"]
```

## Custom matchers

Matchers are declarative TOML files. Drop them anywhere and reference
from `[matchers].extra_paths`:

```toml
# my-matchers/internal.toml
[[matcher]]
slug = "internal-magic-cookie"
description = "Internal magic-cookie auth bypass header"
noise_tier = "precise"
file_patterns = ["**/*.ts", "**/*.go"]
patterns = ["X-Internal-Bypass\\s*:\\s*"]
label = "internal bypass header check"

[matcher.requires]
tech = ["nextjs", "express"]
```

The bundled pack lives at `crates/deepsec-scanner/matchers/*.toml`. Run
`deepsec list-matchers` to see the embedded set.

## On-disk layout

```
data/<projectId>/
├── project.json           # project metadata
├── tech.json              # detected framework tags
├── files/<rel>.json       # FileRecord per scanned source file
├── runs/<runId>.json      # RunMeta per invocation
└── reports/<...>.md|.json|.csv
```

The format is wire-compatible with the original TS implementation, so you
can switch back and forth on the same `data/` directory if you need to
compare results.

## Crates

| Crate                | Role                                                       |
|----------------------|------------------------------------------------------------|
| `deepsec-core`       | Types, paths, JSON persistence                             |
| `deepsec-scanner`    | File walking, tech detection, TOML matcher engine          |
| `deepsec-processor`  | AI pipeline; `AgentBackend` trait + HTTP backends          |
| `deepsec-cli`        | The `deepsec` binary                                       |

## License

Apache-2.0
