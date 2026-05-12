# Architecture

## Packages

```
internal/core           types, paths, persistence
       ▲
       │
internal/scanner        walker, tech-detect, TOML matcher engine
       ▲
       │
internal/processor      AI pipeline; AgentBackend interface
internal/processor/providers
       ▲
       │
internal/cli            cobra command tree
       ▲
       │
cmd/deepsec             the binary
```

Strictly downward dependencies. `core` knows nothing about agents,
scanning, or the CLI.

## Pipeline

```
                 ┌──────────┐
                 │   scan   │   regex-driven; writes FileRecords with candidates
                 └────┬─────┘
                      │
                      ▼
                 ┌──────────┐
                 │ process  │   batches by directory, calls AgentBackend
                 └────┬─────┘
                      │   findings persisted
                      ▼
        ┌─────────────┼─────────────┐
        │             │             │
        ▼             ▼             ▼
 ┌──────────┐  ┌────────────┐  ┌────────┐
 │  enrich  │  │ revalidate │  │ triage │  per-finding actions
 └────┬─────┘  └─────┬──────┘  └────┬───┘
      │              │              │
      └──────────────┴──────────────┘
                     │
                     ▼
              ┌────────────┐
              │ report /   │   markdown, JSON, CSV, SARIF
              │ pr-comment │
              └────────────┘
```

## Concurrency model

`Process` runs in `errgroup` with a `golang.org/x/sync/semaphore` cap on
in-flight batches (default 4). Each batch goroutine acquires a permit,
calls `AgentBackend.Investigate`, and releases on return.

Two cancellation sources both flip a shared `context.CancelFunc`:

- **Quota errors** (`QuotaExhaustedError` from a backend). The run
  records the failure on the affected batch, cancels, and lets the
  remaining batches drain. All cancelled batches' file locks release
  back to `pending` (recoverable on retry), not `error`.
- **Budget cap** (`--max-cost-usd <N>`). When cumulative cost crosses
  the threshold, the run cancels just like a quota failure.

Results are applied to FileRecords sequentially after all goroutines
return, so concurrent batches never fight over the same record.

## Provider registry

`internal/processor/providers` parses an embedded `profiles.toml` (six
built-in providers) plus any user-defined `[providers.<name>]` blocks
from `deepsec.config.toml`. Each profile resolves to one of two backend
implementations:

- `AnthropicBackend` — uses `github.com/anthropics/anthropic-sdk-go`.
  Prompt caching via `cache_control: ephemeral`. Tool use via a
  registered `report_findings` tool.
- `OpenAICompatibleBackend` — uses `github.com/openai/openai-go`.
  Capability flags (`tool_use`, `prompt_cache`, `structured_output`)
  drive per-provider adaptation. The same code path serves OpenAI,
  Azure, OpenRouter, GLM, Kimi, DeepSeek, vLLM, Together, Groq, and
  llama.cpp.

Adding a backend = one `AgentBackend` Go type + a `Kind` constant +
one branch in `NewBackend`. Adding a *provider* = one TOML block.

## Persistence semantics

- Every disk write goes through `AssertSafeSegment` /
  `AssertSafeFilePath` in `internal/core/paths.go`. `..`, null bytes,
  backslashes, and absolute paths are rejected at the API boundary.
- `FileRecord` is append-only for `candidates`, `findings`, and
  `analysisHistory`. Re-scans dedup candidates by
  `(vulnSlug, matchedPattern, lineNumbers)`. Re-processes dedup
  findings by `(vulnSlug, title)`.
- `RunMeta` is written twice: once at `phase=running` so a crashed run
  is recoverable, then again at `phase=done|error` on completion.
- Locking: `Process` writes `status=processing`, `lockedByRunId`,
  `lockedAt` for every record in the work set before dispatching
  batches. Quota / cancelled batches release back to `pending`.

## Prompt assembly

`AssemblePrompt(batch) → (system, user)` composes:

- `CorePrompt` (constant, in `prompt.go`).
- Framework-specific highlights keyed by detected-tech tag
  (`HighlightForTag`).
- Per-matcher reasoning hints keyed by `vulnSlug` (`NoteForSlug`).
- `info_markdown` and `prompt_append` from the project config.

The system prompt is stable across a run, which makes prompt caching
(Anthropic `cache_control: ephemeral`) hit on every batch after the
first.

The user message lists files in the batch with their candidate matches
followed by line-numbered source. The model returns structured output
via tool use (or JSON-mode fallback).
