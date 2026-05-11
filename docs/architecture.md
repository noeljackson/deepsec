# Architecture

## Crates

```
deepsec-core        ─→ types, paths, persistence
       ▲
       │
deepsec-scanner     ─→ walker, tech-detect, TOML matcher engine
       ▲
       │
deepsec-processor   ─→ AI pipeline; AgentBackend trait
       ▲
       │
deepsec-cli         ─→ `deepsec` binary
```

Each crate depends only on the ones above it. There is no circular
dependency; `deepsec-core` knows nothing about agents or scanning.

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
              │ report /   │   markdown, JSON, CSV; PR comment markdown
              │ pr-comment │
              └────────────┘
```

## Concurrency

`process` drives batches in parallel via
`tokio::sync::Semaphore` + `futures::stream::FuturesUnordered`. The
`--concurrency N` flag caps in-flight batches (default 4).

Quota exhaustion (HTTP 429 + provider-specific "out of quota" bodies)
flips a shared `AtomicBool`. Batches waiting on a permit observe the
flag and return a cancelled marker; the run completes with
`quota_exhausted=true` rather than spamming the provider.

## Persistence semantics

- Every disk write goes through `assert_safe_segment` /
  `assert_safe_file_path` in `deepsec-core/src/paths.rs`. `..`, null
  bytes, backslashes, and absolute paths are rejected at the API
  boundary.
- `FileRecord` is append-only for `candidates`, `findings`, and
  `analysisHistory`. Re-scans dedup candidates by
  `(vulnSlug, matchedPattern, lineNumbers)`. Re-processes dedup
  findings by `(vulnSlug, title)`.
- `RunMeta` is written twice: once at `phase=running` so a crashed run
  is recoverable, then again at `phase=done|error` on completion.
- Locking: `process` writes `status=processing`, `lockedByRunId`,
  `lockedAt` for every record in the work set before dispatching
  batches. Stale locks (>1h) from runs that have since completed are
  reclaimable by later invocations.

## Agent backends

`AgentBackend` is an async trait with three methods:

```rust
#[async_trait]
pub trait AgentBackend: Send + Sync {
    fn kind(&self) -> AgentBackendKind;
    fn model(&self) -> &str;
    async fn investigate(&self, batch: &InvestigateBatch) -> Result<InvestigateOutput, ProcessorError>;
    async fn revalidate(&self, input: &RevalidateInput) -> Result<(...), ProcessorError>;
    async fn triage(&self, input: &TriageInput) -> Result<(...), ProcessorError>;
}
```

Both bundled backends speak HTTP directly with `reqwest`. There is no
Node SDK in the dependency tree.

To add a backend, implement the trait, register a `from_str` variant
in `AgentBackendKind`, and add a branch in `make_backend`.

## Prompt assembly

`assemble_prompt(batch)` produces a `(system, user)` tuple from:

- `CORE_PROMPT` (constant, in `prompt/core_prompt.rs`).
- Framework-specific highlights keyed by detected-tech tag
  (`highlight_for_tag`).
- Per-matcher reasoning hints keyed by `vulnSlug` (`note_for_slug`).
- `info_markdown` and `prompt_append` from the project config.

The `user` message lists files in the batch with their candidate
matches followed by line-numbered source. The model is instructed to
return JSON only (`{ "findings": [...] }` or `{ "refusal": "..." }`).
