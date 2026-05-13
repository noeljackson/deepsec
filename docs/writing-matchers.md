# Writing matchers

Matchers are declarative TOML records. The bundled pack lives in
`internal/scanner/matchers/*.toml` and is embedded into the binary at
compile time via `go:embed`. Custom matchers load at runtime via
`[matchers].extra_paths` in `deepsec.config.toml`.

## Minimal example

```toml
# my-matchers/internal.toml
[[matcher]]
slug = "internal-magic-cookie"
description = "Internal magic-cookie auth bypass header"
noise_tier = "precise"
file_patterns = ["**/*.ts", "**/*.go"]
patterns = ["X-Internal-Bypass\\s*:\\s*"]
label = "internal bypass header check"
```

Reference it:

```toml
# deepsec.config.toml
[matchers]
extra_paths = ["./my-matchers/internal.toml"]
```

Verify it loaded: `deepsec list-matchers | grep internal-magic-cookie`.

## Schema

| Field                  | Type            | Required | Default | Notes |
|------------------------|-----------------|----------|---------|-------|
| `slug`                 | string          | yes      |         | Stable identifier; used in `vulnSlug`. |
| `description`          | string          | yes      |         | Short human description (shown in `list-matchers`). |
| `noise_tier`           | enum            | no       | `normal`| `precise` \| `normal` \| `noisy`. |
| `file_patterns`        | string[]        | yes      |         | Doublestar globs evaluated against the relative path. |
| `patterns`             | string[]        | yes      |         | Go regex patterns. Any match produces a candidate. |
| `suppress_patterns`    | string[]        | no       | `[]`    | If any matches the snippet window, the hit is dropped. |
| `require_content`      | string[]        | no       | `[]`    | ALL must match somewhere in the file or the matcher is a no-op. |
| `require_taint_within` | int             | no       | `0`     | Drop candidates that aren't within this many lines of a per-language taint source (`r.URL.Query`, `req.body`, `request.args`, `@RequestParam`, etc.). `0` disables. Per-language sources are defined in `internal/scanner/taint.go`. |
| `exclude_path_patterns`| string[]        | no       | `[]`    | Path regexes to skip (e.g. `\\.test\\.ts$`). |
| `snippet_before`       | int             | no       | `1`     | Lines of context BEFORE the match in `snippet`. |
| `snippet_after`        | int             | no       | `5`     | Lines of context AFTER the match in `snippet`. |
| `label`                | string          | no       | regex literal | What's stored in `matchedPattern`. |
| `requires.tech`        | string[]        | no       | `[]`    | Gate: matcher runs only if one of these detect-tech tags is present. |
| `requires.sentinel_files` | string[]     | no       | `[]`    | Gate: matcher runs if any path/glob exists under the root. |
| `requires.sentinel_contains` | string[]  | no       | `[]`    | If `sentinel_files` matches, also require one of these regexes in the body. |

`requires.tech` and `requires.sentinel_files` are unioned (OR).

## Regex flavor — RE2, not PCRE

Go's `regexp` package uses RE2: linear-time guarantee (no catastrophic
backtracking), no support for backreferences or lookaround.

**Not supported** — rewrite patterns that use:

- `(?=...)`, `(?!...)`, `(?<=...)`, `(?<!...)` (lookaround)
- `\1`, `\2` (backreferences)

**Workarounds:**

- Negative lookahead → use `suppress_patterns` to drop hits whose
  snippet window contains the forbidden text:
  ```toml
  # WRONG: yaml.load not followed by SafeLoader
  # patterns = ["yaml\\.load\\([^)]*(?!SafeLoader)"]
  patterns = ["yaml\\.load\\("]
  suppress_patterns = ["SafeLoader"]
  ```

- Conditional matching → enumerate the closed set as an alternation
  (e.g. for "USER root then later a non-root USER", spell out common
  non-root names: `nobody|app|node|deploy|nginx|service|www-data|[0-9]+`).

Inline flags work: `(?i)`, `(?m)`, `(?s)`. **Always quote backslashes in
TOML**: `"\\b"`, not `"\b"`.

## Tips

- **Anchor framework-aware matchers with `requires.tech`** so they
  don't fire on every file in every repo. `tech = ["nextjs"]` is enough.
- **Use `require_content` to short-circuit** on files that don't
  import the relevant SDK. Saves regex work on large repos.
- **Pair noisy patterns with a tight `file_patterns`**. A `noisy`
  matcher with `**/*.ts` will hit thousands of irrelevant files.
- **Skip tests via `exclude_path_patterns`**:
  ```toml
  exclude_path_patterns = ["\\.(test|spec)\\.[jt]sx?$", "node_modules/"]
  ```

## Testing matchers

Drop into the fixture and inspect the output:

```bash
cd /tmp && mkdir t && cd t
cp -R <path-to>/deepsec/fixtures/vulnerable-app ./app
deepsec init --project-id t --root ./app
deepsec scan --project-id t --matchers my-slug
grep -l my-slug data/t/files/**/*.json
```

For Go-native unit tests, add a `_test.go` next to
`internal/scanner/matcher.go` that compiles a TOML inline and asserts
hits via `Matcher.Match(content, file)`.
