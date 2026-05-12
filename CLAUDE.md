# CLAUDE.md

Pointer file for Claude Code working in this repo. User-facing docs are
in [README.md](./README.md); contributor docs in
[CONTRIBUTING.md](./CONTRIBUTING.md). Read those first.

## Repo shape

This is a Go module.

```
cmd/deepsec/                 The CLI binary
internal/
  core/                      Types, paths, schemas, JSON persistence
  scanner/                   File walker, tech detection, TOML matcher engine
    matchers/                Embedded bundled matcher pack (*.toml)
  processor/                 AI pipeline (AgentBackend + Anthropic/OpenAI backends)
    providers/               Provider registry; profiles.toml is embedded
  cli/                       Cobra context, file_sources, preflight
    commands/                Each subcommand in its own file
fixtures/vulnerable-app/     Planted-vulnerability fixture for tests
docs/                        User-facing docs
```

## Commands

```bash
go build ./cmd/deepsec               # build the binary
go test ./...                        # unit + integration tests
go test ./... -race -count=1         # full suite with race detector
go vet ./...                         # static analysis
gofmt -l .                           # format check
```

## Patterns to keep in mind

- Matchers are declarative TOML, embedded via `go:embed
  matchers/*.toml` in `internal/scanner/registry.go`. User-defined
  matchers go in TOML files referenced from `[matchers].extra_paths`.
- The wire format on disk (`data/<projectId>/files/*.json`,
  `runs/*.json`) matches the original TypeScript implementation. Don't
  break JSON tags in `internal/core/types.go` without thought.
- AI backends live in `internal/processor/`. There are exactly two
  implementations (`AnthropicBackend`, `OpenAICompatibleBackend`); new
  providers are added as TOML profile entries, not new Go types.
- Provider profile caps (`tool_use`, `prompt_cache`,
  `structured_output`) drive per-provider adaptation in the
  OpenAI-compatible backend — see `applySchemaFor` in
  `openai_backend.go`.
- Path-safety: every disk write goes through `AssertSafeSegment` /
  `AssertSafeFilePath` in `internal/core/paths.go`. Do not bypass.
- Concurrency: `Process` uses `errgroup` + `semaphore.Weighted`.
  Quota or budget exhaustion calls `cancel()` so in-flight batches
  abort with `context.Canceled`; releases their locks back to
  `pending` so the user can retry.
