# deepsec

`deepsec` is an agent-powered vulnerability scanner that you run in your
own infrastructure to perform on-demand security review of large repos.

A regex-and-AST scanner produces high-recall *candidate* matches; a
configurable AI backend then investigates each candidate against the
actual source code and emits real findings — severity, confidence,
recommendation, and revalidatable verdicts on each one. Optional
companion tooling autonomously improves the matcher pack against a
labeled benchmark, gated on statistical significance and Pareto-style
regression checks.

> **Origin.** deepsec started as a Vercel-internal TypeScript prototype
> for AI-assisted security review of large monorepos. It was rewritten
> in Go for distribution as a single static binary that fits the
> distroless / CI-image story. The original TypeScript is preserved in
> git history (see commits before `claude/rewrite-deepsec-go`).

## Universal-scanner invariant

deepsec aims to work equally well on every language. The bundled
matcher pack reflects continued investment toward parity:

| Tier | Languages |
|---|---|
| **Strong** (20+ matchers) | TypeScript/JSX, Python, Go, Ruby |
| **Mid** (10–19) | Java, Rust |
| **Weak** (5–9) | PHP, C#, Swift, Kotlin, C, C++ |

Coverage gaps are bugs. File an issue tagged with the language if you
hit one, or send a matcher-pack PR. The AST roadmap
([RFC 001](docs/rfcs/001-ast-matching.md)) lands Go + TS + Python as
Phase 1; **Rust + Java are now shipped (Phase 2)**, with Kotlin /
Swift / C / C++ as funded Phase 3 — not "someday".

## Install

Pre-built binaries for linux / darwin / windows × amd64 / arm64 are
published per-release. Or build from source:

```bash
go install github.com/noeljackson/deepsec/cmd/deepsec@latest
```

…or clone and build:

```bash
git clone https://github.com/noeljackson/deepsec
cd deepsec
go build -o bin/deepsec ./cmd/deepsec
```

A `Dockerfile` (distroless static, ~20 MB) is also available:

```bash
docker build -t deepsec .
docker run --rm -v $PWD:/work -w /work -e ANTHROPIC_API_KEY deepsec scan --project-id myproj
```

## Quick start

```bash
# in the repo you want to scan
deepsec init --project-id myproj --root .

# sanity-check the setup (config, providers, matchers, AST grammars)
deepsec doctor

# run the scanner (regex + AST matchers, gated on detected tech)
deepsec scan --project-id myproj

# investigate the candidates with an AI backend
export ANTHROPIC_API_KEY=sk-ant-...
deepsec process --project-id myproj --agent anthropic --concurrency 4

# optional: let the investigator read related files before reporting
deepsec process --project-id myproj --agent anthropic --tools --max-turns 8

# render a human-readable report
deepsec report --project-id myproj
```

If anything looks wrong — empty candidate set, "providers: 0 with
keys", an AST grammar that didn't load — run `deepsec doctor
--verbose` first. The output maps directly to entries in
[`docs/troubleshooting.md`](docs/troubleshooting.md).

Full docs map: [`docs/index.md`](docs/index.md).

## What's special about deepsec

### A pipeline that's auditable end-to-end

Every stage writes to a canonical on-disk format under
`data/<projectId>/`. Stages are idempotent: re-running merges new
information rather than overwriting. Every finding traces back through
`AnalysisHistory` to the exact LLM call, model, prompt version, and
matcher pack hash that produced it. The compliance-formatted output
(`deepsec report --format soc2`) bundles that provenance with an
HMAC-signed manifest auditors can verify offline.

### AST-aware matchers, not just regex

deepsec embeds tree-sitter grammars and runs them through
[wazero](https://github.com/tetratelabs/wazero) — pure Go, no CGo, no
external runtime. AST matchers can express things like *"match a
`Call` whose callee is `exec.Command` and whose first argument is a
binary expression involving a tainted identifier"* directly in
[tree-sitter S-expression queries](docs/writing-ast-matchers.md). On
the worked example (`bench/tasks/go-vulnerable-cli`), the AST version
of `go-http-handler` moves precision from 0.50 → 1.00 with zero false
positives.

### An auto-learn loop you can actually run

The bundled scanner is a starting point; the [auto-learn loop](docs/auto-learn-loop.md)
keeps it tuned. Labeled bench fixtures (which can pin a real repo at a
SHA without copying source into your tree), bootstrap-CI scoring, a
human-in-the-loop matcher review CLI, and an autonomous bounded-patch
agent — all wired together, with statistical gates and a `needs-engine-feature`
escape valve when a regex narrowing isn't safe.

Findings can also move into source fixes with `deepsec patch`. The
patcher asks the configured AI backend for a strict JSON unified diff,
applies it in a throwaway clone/copy, runs an optional validation
command such as `go test ./...`, and writes provenance under
`data/<project>/patches/`. `--apply` commits the validated diff on a
`deepsec-patch/<finding-id>` branch; `--push` additionally opens a PR
through `gh`.

```
matcher TOMLs ─► scan ─► candidates ─► process ─► findings
       ▲                                            │
       │                                            ▼
       │      ┌──────────────────────┐    bench scorer
       │      │ supervised review CLI │ ◄─ bootstrap CIs
       │      │ autonomous loop       │
       │      └──────────────────────┘
       │                │
       └────── regression cases + commit
```

Start at [`docs/auto-learn-loop.md`](docs/auto-learn-loop.md) for the
one-screen tour.

### Multiple AI backends, your choice

`deepsec` ships with six provider profiles. Two backend implementations
cover all of them:

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
| Z.ai (GLM)   | `glm`        | `ZAI_API_KEY`        | `glm-5.1`                  |
| Z.ai Coding Plan | `zai-coding` | `ZAI_API_KEY`    | `glm-5.1`                  |
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
   scan          process        revalidate          enrich           export / report
    │              │                │                │                      │
    ▼              ▼                ▼                ▼                      ▼
candidates  →   findings    TP/FP/Fixed verdict  →  +committers  →   JSON / md / SARIF / SOC2
                                                    +ownership
```

| Stage         | What it does                                                      |
|---------------|-------------------------------------------------------------------|
| `scan`        | Walk files, run regex + AST matchers gated on detected tech.      |
| `process`     | Batch FileRecords by directory; ask the AI to confirm / reject.   |
| `revalidate`  | Re-check existing findings against current source: TP/FP/fixed.   |
| `triage`      | Assign priority/exploitability/impact.                            |
| `enrich`      | Populate gitInfo.recentCommitters via `git log`.                  |
| `report`      | Markdown + JSON + CSV per project, or compliance-formatted JSON.  |
| `export`      | Filtered JSON or SARIF (for GitHub Code Scanning).                |
| `pr-comment`  | Markdown for net-new findings from a specific run.                |
| `data-commit` | `git add data/ && git commit` to version your scan results.       |
| `metrics`     | Aggregate cost, tokens, TP/FP rates across runs.                  |

Run `deepsec --help` for the full command list, `deepsec <cmd> --help`
for flags on a specific command.

## CI / pull-request workflow

```bash
deepsec scan --project-id myproj --diff origin/main
deepsec process --project-id myproj --diff origin/main --concurrency 8 \
  --temperature 0 --seed 1
deepsec pr-comment --project-id myproj --output pr-comment.md --skip-empty
```

The `--diff <ref>` flag bounds the work to files changed against the
given git ref. `--temperature 0 --seed N` pins the LLM sampler so
repeated PR runs produce the same findings against the same code.
`process --tools` enables the multi-turn read-only investigator tools
documented in [`docs/agentic-tools.md`](docs/agentic-tools.md); leave it
off for the lowest-latency CI path.
`pr-comment` filters to findings whose `producedByRunId` matches the
most recent process run.

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

For AST-aware matchers, extend with `[[matcher.ast_patterns]]` blocks
using tree-sitter S-expression queries — see
[docs/writing-ast-matchers.md](docs/writing-ast-matchers.md).

Run `deepsec list-matchers` to see the embedded set (~80 matchers
across core security, secrets, crypto, framework entry points, infra,
and AI/agentic patterns).

## Compliance-formatted reports

For SOC 2, ISO 27001, FedRAMP, or NIST SSDF evidence:

```bash
export DEEPSEC_REPORT_SIGNING_KEY="rotate-this-secret"
deepsec report --project-id myproj --format soc2 --output evidence.json

# verify later
deepsec report --verify evidence.json
```

The report includes a manifest (scanner version, matcher pack hash,
prompt pack hash, provider/model used, total cost) and per-finding
provenance (deterministic `finding_id`, `evidence_hash` binding to file
content at scan time, status). Signed with HMAC-SHA256. Schema
versioned at `1.0`. See
[docs/compliance-reporting.md](docs/compliance-reporting.md).

## External bench fixtures

The bench can pin a real OSS repo at a SHA without copying its source
into the deepsec tree:

```toml
# bench/tasks/<task>/task.toml
[repo]
url    = "https://github.com/tailscale/tailscale.git"
commit = "<pinned-sha>"
```

Source is shallow-cloned per scoring run and removed when the run ends.
Lets the bench grow toward realistic-scale corpora without licensing or
IP concerns. See [bench/README.md](bench/README.md).

## On-disk layout

```
data/<projectId>/
├── project.json
├── tech.json
├── files/<rel>.json       # FileRecord per scanned source file
├── runs/<runId>.json      # RunMeta per invocation
└── reports/
```

Same camelCase JSON shape as the original Vercel TypeScript
implementation — existing `data/` directories carry over unchanged.

## Packages

| Path                              | Role                                        |
|-----------------------------------|---------------------------------------------|
| `internal/core`                   | Types, paths, JSON persistence              |
| `internal/scanner`                | Walker, tech detection, TOML matcher engine |
| `internal/scanner/ast`            | tree-sitter via wazero (AST matching)       |
| `internal/scanner/matchers/*.toml`| Embedded matcher pack                       |
| `internal/scanner/regressions`    | Regression-case loader (TOML-driven tests)  |
| `internal/processor`              | AI pipeline; AgentBackend                   |
| `internal/processor/prompts`      | Externalised prompt files                   |
| `internal/processor/providers`    | Provider registry + profiles                |
| `internal/processor/mockbackend`  | Deterministic replay backend for bench eval |
| `internal/cli`                    | Shared context + helpers                    |
| `internal/cli/commands`           | Cobra subcommands                           |
| `cmd/deepsec`                     | The CLI binary                              |
| `cmd/benchsec`                    | The benchmark / scorer / agent CLI          |
| `bench/`                          | Labeled fixtures + scorer + scoring math    |
| `docs/`                           | User-facing docs                            |
| `docs/rfcs/`                      | Architecture RFCs                           |

## License

Apache-2.0.
