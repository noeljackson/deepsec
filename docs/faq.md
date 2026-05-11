# FAQ

## Why is this a rewrite?

The original implementation was TypeScript, with TS-only matcher
modules and tight coupling to the Anthropic and OpenAI Node SDKs. The
Rust rewrite makes the scanner self-contained, declarative
(TOML-driven matchers), and provider-agnostic (HTTP backends behind a
single trait).

## Can I switch back to the TS version?

The on-disk `data/<projectId>/` format is wire-compatible. Running the
old TS tool against a data directory written by the Rust tool (and
vice-versa) works.

## How do I add a new AI backend?

Implement `AgentBackend` in `crates/deepsec-processor/src/agents/`,
register a `from_str` variant in `AgentBackendKind`, and add a branch
in `make_backend`. See the Anthropic backend for the smallest example.

## Can I use a local model?

Yes. Point `OPENAI_BASE_URL` at any OpenAI-compatible server:

- `OPENAI_BASE_URL=http://localhost:8080` with `llama.cpp --server`
- `OPENAI_BASE_URL=https://your-vllm.example.com/v1` (drop the `/v1`
  if the server already includes it)
- `OPENAI_BASE_URL=https://openrouter.ai/api`

## How much does a scan cost?

Whatever the provider charges for input + output tokens. `deepsec
metrics --project-id <id>` aggregates `totalCostUsd` across runs from
each `RunMeta.stats`. Note: cost reporting is only as accurate as the
backend's response; for backends that don't return cost, the field is
zero.

## What's the difference between `revalidate` and `triage`?

`revalidate` re-checks an existing finding against the *current* file
and assigns a verdict: `true-positive` / `false-positive` / `fixed` /
`uncertain` / `accepted-risk`. Use it after a fix lands to confirm the
issue is gone, or to age out stale findings.

`triage` assigns priority (P0/P1/P2/skip), exploitability, and impact
to an unverdicted finding. It doesn't re-read the file's current
content; it's a pure-policy call.

## Why TOML instead of YAML / JSON?

TOML's quoting rules are easier to get right for regex-heavy content
than YAML's, and unlike JSON it supports comments. The trade-off is
that escaping backslashes is mandatory (`"\\b"`).

## How do I run only a subset of matchers?

```toml
[matchers]
only    = ["auth-bypass", "sql-injection-string-concat"]
# or
exclude = ["nextjs-route-no-auth"]
```

Or on the CLI: `deepsec scan --project-id <id> --matchers a,b,c`.

## How is concurrency bounded?

`process --concurrency N` (default 4) uses a `tokio::sync::Semaphore`
to cap in-flight batches. Within a batch, all files are sent in one
request. With `--batch-size 1 --concurrency 8`, each file is a
separate request, eight in flight.

## Is there a daemon mode?

No. `deepsec` is a one-shot CLI. State lives entirely on disk in
`data/`. If you need continuous scanning, run it from cron or your CI.
