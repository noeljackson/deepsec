# External Prompt Refactor Results

- Branch: `prompts/extern-A`
- Files/formats:
  - `internal/processor/prompts/core.md`: Markdown/plain text for the core system prompt, so the prompt body is directly editable as prose.
  - `internal/processor/prompts/framework_hints.toml`: TOML `[[highlight]]` entries keyed by detected tech tag.
  - `internal/processor/prompts/slug_hints.toml`: TOML `[[note]]` entries keyed by matcher slug.
- Loader structure: `internal/processor/prompts` embeds the three files with one `go:embed` directive. The profile is loaded eagerly at package init; malformed data panics through `mustLoad`, while the exported `Load(fs.FS)` returns errors for tests/future profile work.
- Validation: TOML is decoded strictly with `MetaData.Undecoded`; malformed files, unknown keys, duplicate keys, empty keys/text, missing files, and empty core prompt are rejected.
- Golden-test result: pass. `TestAssemblePromptGolden` generated fixtures from the pre-refactor inline implementation, and the refactor matches the system/user output byte-for-byte. No prompt text massage was needed.
- Net LOC delta: +497 lines (577 insertions, 80 deletions) in the staged diff.
- Surprises: `go test ./...` first failed because this environment could not execute test-built binaries from `/tmp`; rerunning with a repo-local `TMPDIR` reached the CLI HTTP-backend tests, but those existing end-to-end tests failed because subprocesses did not successfully use their local `httptest` Anthropic server. The prompt/processor test suite passes independently.
