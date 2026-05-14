# Troubleshooting

Companion to `deepsec doctor`. Run that first.

```bash
deepsec doctor                       # config + providers + matchers + AST
deepsec doctor --project-id myproj   # adds project + tech + scan summary
deepsec doctor --verbose             # lists every provider, matcher, etc.
```

Symbols:

- `✓` everything green
- `⚠` warning — won't block, but worth knowing
- `✗` failed — fix before proceeding

Below: common failure modes in the order you're likely to hit them.

## `no deepsec.config.toml`

You haven't initialised the project yet.

```bash
deepsec init --project-id myproj --root .
```

The `init` writes `deepsec.config.toml` in the current directory and a
`[[projects]]` entry. If you have a multi-project monorepo, add more
entries by hand or run `deepsec init-project --project-id …`.

## `0 with keys set; AI investigation will fail`

The matcher pack runs without an API key (regex + AST is offline), but
`deepsec process` needs an LLM. Set one of:

| Provider | env var |
|----------|---------|
| Anthropic | `ANTHROPIC_API_KEY` |
| OpenAI | `OPENAI_API_KEY` |
| Z.ai (GLM / Coding Plan) | `ZAI_API_KEY` |
| Kimi | `MOONSHOT_API_KEY` |
| DeepSeek | `DEEPSEEK_API_KEY` |
| OpenRouter | `OPENROUTER_API_KEY` |

Then `deepsec process --agent <provider> --project-id myproj`.

Z.ai gotcha: a Coding-Plan key is valid for `zai-coding` (Anthropic-compatible
endpoint) but NOT for `glm` (pay-as-you-go OpenAI-compatible). If `glm`
errors with "0 findings, all batches failed," that's the cause. Use
`zai-coding` instead. See PR #74's fix for the silent-failure mode.

## `scan` returns 0 candidates

`deepsec doctor --project-id <id> --verbose` shows you which matchers
were gated out and which were active.

- **All matchers gated out**: tech detection didn't fire any tags. Check
  `--verbose` "tech detected" line. Usual cause: project root isn't
  what you think it is. The doctor prints the resolved root.
- **No matchers fire on files you expect**: `file_patterns` glob may
  not match. Doublestar globs are relative to the project root.
- **`require_content` keywords aren't present**: a matcher with
  `require_content = ["express"]` skips files where neither the
  imports nor the body mentions Express. This is by design.

## `process` returns 0 findings

If candidates exist but findings don't, the AI investigation phase
dropped them all. Causes:

- **Refusals**: the model refused. Look in
  `data/<project>/files/<file>.json` for `refusal` entries.
- **Skeptic dropped them all**: `--skeptic` is aggressive. Try without
  it for the first pass.
- **Quota exhausted**: `data/<project>/runs/<runid>.json` records
  `quotaExhausted: true`. Wait or rotate the key.

## `AST grammar failed to load`

The doctor prints "AST grammars: N loaded" — if N < 12, one or more
WASMs failed.

```bash
deepsec doctor --verbose
```

The verbose output includes any load error from the wazero bridge. Most
common cause: a grammar refresh that imported a new libc symbol the
bridge doesn't yet provide. See
[refreshing-grammars.md](./refreshing-grammars.md) — the fix is to add
the symbol to `bridgeFuncImports` and `instantiateLibcHost` in
`internal/scanner/ast/wazero_abi.go`.

## `permission denied` running `scripts/build-grammar-wasm.sh`

The script runs npm install inside docker and writes to
`$REPO/.cache/grammar-build/`. If `/tmp` is mounted noexec on your
host (some hardened distros), the script already routes around that —
but if `.cache/grammar-build/` itself isn't writable, fix permissions
or set a different `SCRATCH_PARENT`.

If docker is unavailable, the script can't run. Phase 3 grammars
(kotlin / swift / c / cpp) require this — Phase 1 / 2 grammars are
already-built WASMs in `internal/scanner/ast/grammars/`.

## `process` extremely slow

Two common causes:

- **Concurrency is 1**: default is 4. Bump with `--concurrency 8`.
- **`--tools` and `--max-turns` high**: agentic tool-use loops can run
  4-8 turns per file. Drop `--max-turns 4` or omit `--tools` for the
  fast path.

`deepsec process --record` writes a JSONL replay you can re-investigate
offline against captured responses; useful for measuring the AI side
without retrying it.

## CI: `go test` fails with `permission denied`

Usually `/tmp` mounted noexec on the runner. CI uses `TMPDIR=$PWD/.tmp`
in some test paths. If you see `fork/exec /tmp/...: permission denied`
in `TestCLI*` tests, that's the cause. The flake is environmental, not
a regression in deepsec.

## CI: bench advisory job ❌

The advisory bench job (PR #92) flags recall/precision regressions
against `bench/baseline.json` on main. A ❌ means a matcher edit or
prompt change moved the numbers; it doesn't block merge but signals a
review. To see the diff locally:

```bash
benchsec score > /tmp/pr-score.json
diff <(jq . bench/baseline.json) <(jq . /tmp/pr-score.json) | less
```

The full bench gate semantics + bootstrap-CI thresholds are documented
in [bench-task-format.md](./bench-task-format.md).

## I want to verify my install end-to-end

```bash
# Quick sanity
deepsec --help
deepsec doctor

# Scan deepsec on itself (cheap, no API calls)
deepsec scan --project-id deepsec     # if it's the current repo
```

A clean `doctor` plus a successful `scan` proves the pipeline up to
the AI step. Add an API key and re-run with `process` for the rest.

## Still stuck

- See [docs/index.md](./index.md) for the full doc map.
- File an issue at https://github.com/noeljackson/deepsec/issues. Include
  the output of `deepsec doctor --verbose` if at all relevant — it makes
  diagnosis ~5× faster.
