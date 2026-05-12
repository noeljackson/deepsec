# FAQ

## Why Go?

The original implementation was TypeScript. The Go rewrite is driven
by two things:

1. **Anthropic + OpenAI ship official Go SDKs.** Prompt caching, tool
   use, structured outputs, retry semantics, error taxonomy — all
   maintained by the vendor instead of hand-rolled.
2. **Single static binary** for distribution, no Node runtime drift in
   CI, trivial cross-compilation.

The TS code remains in git history if you need to reference it.

## Can I switch between Go and TS versions?

The on-disk `data/<projectId>/` format is wire-compatible (identical
camelCase JSON shapes). A directory written by either tool reads from
the other.

## How do I use Z.ai (GLM), Kimi, or DeepSeek?

They ship enabled by default, you just need their API key:

```bash
export ZAI_API_KEY=...
deepsec process --project-id myproj --agent glm
```

`list-providers` shows which env vars are set. All three implement
OpenAI-compatible APIs and route through the same backend code.

## Can I use a local model?

Yes. Add a custom provider in `deepsec.config.toml` pointing at any
OpenAI-compatible server:

```toml
[providers.local]
kind = "openai-compatible"
base_url = "http://localhost:8080/v1"
api_key_env = "LOCAL_KEY"     # set to any non-empty string
default_model = "qwen-2.5-coder"

[providers.local.caps]
tool_use = false              # most local servers don't support reliable tool use
structured_output = "json_object"
prompt_cache = "none"
```

Works with `llama.cpp --server`, vLLM, Ollama (set `LOCAL_KEY=ollama`),
and similar.

## How do I add a new AI backend?

For a new *provider* with an existing API style, just add a
`[providers.<name>]` block. No Go code.

For a fundamentally new backend type (e.g. a Cohere or Mistral
proprietary protocol), implement the `AgentBackend` interface in
`internal/processor/`, add a constant in `internal/processor/providers/registry.go`,
and add a branch in `NewBackend`.

## How much does a scan cost?

Whatever the provider charges. `deepsec metrics --project-id <id>`
aggregates `totalCostUsd` from per-run pricing-table lookups; the
numbers are accurate (multiplied by the per-model `$/Mtok` table in the
provider profile).

For Anthropic, prompt caching cuts the system prompt's cost ~80% after
the first batch. The savings are automatic and shown in `metrics`.

Use `process --max-cost-usd <N>` to abort a run mid-flight when cost
crosses a threshold.

## What's the difference between `revalidate` and `triage`?

- `revalidate` re-checks an existing finding against the *current* file
  and assigns a verdict: `true-positive` / `false-positive` / `fixed`
  / `uncertain` / `accepted-risk`. Use after a fix lands.
- `triage` assigns priority (P0/P1/P2/skip), exploitability, and
  impact. Pure-policy call; doesn't re-read the file.

## How does the SARIF export work?

```bash
deepsec export --project-id myproj --format sarif --output deepsec.sarif
```

The output is a minimal SARIF 2.1.0 document with one rule per
`vulnSlug` and one result per finding. Upload via
`github/codeql-action/upload-sarif` to get inline findings on PRs.

## Is there a daemon mode?

No. `deepsec` is a one-shot CLI. State lives entirely on disk in
`data/`. Run from cron, CI, or `pre-push` git hooks.

## How is concurrency bounded?

`process --concurrency N` (default 4) uses a `semaphore.Weighted` to
cap in-flight batches. Within a batch, all files go in one request.
With `--batch-size 1 --concurrency 8`, each file is a separate
request, eight in flight.

Quota errors and budget caps both flip a shared cancel flag so
in-flight batches drain cleanly. Files released this way go back to
`status=pending` (retryable), not `status=error`.
