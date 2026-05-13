# deepsec

`deepsec` is an agent-powered vulnerability scanner that you run in your
own infrastructure to perform on-demand security review of large repos.

A regex-driven scanner produces high-recall *candidate* matches; a
configurable AI backend then investigates each candidate against the
actual source code and emits real findings — severity, confidence,
recommendation, and revalidatable verdicts on each one.

deepsec is a **universal scanner**: the goal is to work equally well on
every language. The bundled matcher pack today reflects where we
started, not where we're going:

| Tier | Languages |
|---|---|
| **Strong** (20+ matchers) | TypeScript/JSX, Python, Go, Ruby |
| **Weak** (5–10) | Java, Rust, PHP, C# |
| **Sparse** (≤1) | C, C++, Swift, Kotlin |

Coverage gaps are bugs. File an issue tagged with the language if you
hit one, or send a matcher-pack PR. The AST roadmap (RFC 001) lands
Go + TS + Python as Phase 1, Rust + Java as required Phase 2, with
Kotlin / Swift / C / C++ as funded Phase 3 — not "someday".

> **Note.** This is the Go implementation. The original TypeScript code
> is preserved in git history (see `git log` before commit
> `claude/rewrite-deepsec-go`).

## Install

Pre-built binaries are published per-release for linux/darwin/windows
across amd64/arm64. Or build from source:

```bash
go install github.com/noeljackson/deepsec/cmd/deepsec@latest
```

…or clone and build:

```bash
git clone https://github.com/noeljackson/deepsec
cd deepsec
go build -o bin/deepsec ./cmd/deepsec
```

A `Dockerfile` (distroless, ~20 MB) is also available:

```bash
docker build -t deepsec .
docker run --rm -v $PWD:/work -w /work -e ANTHROPIC_API_KEY deepsec scan --project-id myproj
```

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

## Improving deepsec on a benchmark

deepsec ships with an **auto-learn loop**: labeled fixtures, a
deterministic scorer, a human-in-the-loop matcher review CLI, and an
autonomous bounded-patch agent that hill-climbs against the bench.
Start at [`docs/auto-learn-loop.md`](docs/auto-learn-loop.md) for the
one-screen tour with links into each layer.

## AI backends

`deepsec` ships with six provider profiles out of the box. Two backend
implementations cover all of them:

- `anthropic` — uses `github.com/anthropics/anthropic-sdk-go`. Prompt
  caching (`cache_control: ephemeral`) on the system prompt typically
  cuts cost ~80% across a run.
- `openai-compatible` — uses `github.com/openai/openai-go`. Drives any
  OpenAI-compatible server via `base_url`: OpenAI, Azure, OpenRouter,
  GLM, Kimi, DeepSeek, vLLM, Together, Groq, llama.cpp, …

| Provider     | `--agent`    | Env var              | Default model              |
|--------------|--------------|----------------------|----------------------------|
| Anthropic    | `anthropic`  | `ANTHROPIC_API_KEY`  | `claude-sonnet-4-6`        |
| OpenAI       | `openai`     | `OPENAI_API_KEY`     | `gpt-4.1-mini`             |
| GLM (Z.ai)   | `glm`        | `ZAI_API_KEY`        | `glm-5.1`                  |
| Kimi K2      | `kimi`       | `MOONSHOT_API_KEY`   | `kimi-k2-instruct`         |
| DeepSeek     | `deepseek`   | `DEEPSEEK_API_KEY`   | `deepseek-chat`            |
| OpenRouter   | `openrouter` | `OPENROUTER_API_KEY` | `anthropic/claude-sonnet-4.6` |

Run `deepsec list-providers` to see which are configured. Add a custom
provider (Azure deployment, internal gateway, local vLLM) with a TOML
block in `deepsec.config.toml`:

```toml
[providers.my-azure]
kind = "openai-compatible"
base_url = "https://my-resource.openai.azure.com/openai/deployments/gpt-4"
api_key_env = "AZURE_OPENAI_KEY"
default_model = "gpt-4"
headers = { "api-version" = "2024-08-01-preview" }
caps = { tool_use = true, prompt_cache = "auto", structured_output = "json_schema" }
```

## Workflow

```text
   scan          process        revalidate          enrich           export
    │              │                │                │                  │
    ▼              ▼                ▼                ▼                  ▼
candidates  →   findings    TP/FP/Fixed verdict  →  +committers  →   JSON / md / SARIF
                                                    +ownership
```

Every stage is a CLI subcommand operating on the same on-disk format
under `data/<projectId>/`. Stages are idempotent: re-running merges new
information rather than overwriting.

| Stage         | What it does                                                      |
|---------------|-------------------------------------------------------------------|
| `scan`        | Walk files, run regex matchers gated on detected tech.            |
| `process`     | Batch FileRecords by directory; ask the AI to confirm / reject.   |
| `revalidate`  | Re-check existing findings against current source: TP/FP/fixed.   |
| `triage`      | Assign priority/exploitability/impact.                            |
| `enrich`      | Populate gitInfo.recentCommitters via `git log`.                  |
| `report`      | Markdown + JSON + CSV per project.                                |
| `export`      | Filtered JSON or SARIF (for GitHub Code Scanning) export.         |
| `pr-comment`  | Markdown for net-new findings from a specific run.                |
| `data-commit` | `git add data/ && git commit` to version your scan results.       |
| `metrics`     | Aggregate cost, tokens, TP/FP rates across runs.                  |

Run `deepsec --help` for the full command list, `deepsec <cmd> --help`
for flags on a specific command.

## CI / pull-request workflow

```bash
deepsec scan --project-id myproj --diff origin/main
deepsec process --project-id myproj --diff origin/main --concurrency 8
deepsec pr-comment --project-id myproj --output pr-comment.md --skip-empty
```

The `--diff <ref>` flag bounds the work to files changed against the
given git ref. `pr-comment` filters to findings whose `producedByRunId`
matches the most recent process run.

For GitHub Code Scanning:

```bash
deepsec export --project-id myproj --format sarif --output deepsec.sarif
```

Upload `deepsec.sarif` via `github/codeql-action/upload-sarif`.

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
This service handles payments. Pay extra attention to /api/payments.
"""
prompt_append = "When in doubt about authentication boundaries, flag it."
priority_paths = ["src/api/admin/", "src/lib/auth/"]
```

## Custom matchers

Matchers are declarative TOML files. The bundled pack lives at
`internal/scanner/matchers/*.toml` (embedded at compile time). Add your
own and reference from `[matchers].extra_paths`:

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

Run `deepsec list-matchers` to see the embedded set (~80 matchers
across core security, secrets, crypto, framework entry points, infra,
and AI/agentic patterns). Regex uses Go's `regexp` (RE2) — fast,
linear-time, no backreferences or lookahead. See
[docs/writing-matchers.md](docs/writing-matchers.md).

## On-disk layout

```
data/<projectId>/
├── project.json
├── tech.json
├── files/<rel>.json       # FileRecord per scanned source file
├── runs/<runId>.json      # RunMeta per invocation
└── reports/
```

Same camelCase JSON shape as the original TypeScript implementation —
existing `data/` directories carry over unchanged.

## Crates

| Package                         | Role                                        |
|---------------------------------|---------------------------------------------|
| `internal/core`                 | Types, paths, JSON persistence              |
| `internal/scanner`              | Walker, tech detection, TOML matcher engine |
| `internal/processor`            | AI pipeline; AgentBackend                   |
| `internal/processor/providers`  | Provider registry + profiles                |
| `internal/cli`                  | Shared context + helpers                    |
| `internal/cli/commands`         | Cobra subcommands                           |
| `cmd/deepsec`                   | The CLI binary                              |

## License

Apache-2.0
