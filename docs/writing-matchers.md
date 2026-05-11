# Writing matchers

Matchers are declarative TOML records. The bundled pack lives in
`crates/deepsec-scanner/matchers/*.toml` and is embedded into the
binary at compile time. Custom matchers can be loaded at runtime via
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
| `noise_tier`           | enum            | no       | `normal`| `precise` \| `normal` \| `noisy`. Controls batching priority. |
| `file_patterns`        | string[]        | yes      |         | Globs evaluated against the relative path. |
| `patterns`             | string[]        | yes      |         | Regex patterns. Any match produces a candidate. |
| `suppress_patterns`    | string[]        | no       | `[]`    | If any matches the snippet window, the hit is dropped. |
| `require_content`      | string[]        | no       | `[]`    | ALL must match somewhere in the file or the matcher is a no-op. |
| `exclude_path_patterns`| string[]        | no       | `[]`    | Path regexes to skip (e.g. `\\.test\\.ts$`). |
| `snippet_before`       | usize           | no       | `1`     | Lines of context BEFORE the match in `snippet`. |
| `snippet_after`        | usize           | no       | `5`     | Lines of context AFTER the match in `snippet`. |
| `label`                | string          | no       | regex literal | What's stored in `matchedPattern`. |
| `requires.tech`        | string[]        | no       | `[]`    | Gate: matcher runs only if one of these detect-tech tags is present. |
| `requires.sentinel_files` | string[]     | no       | `[]`    | Gate: matcher runs if any path/glob exists under the root. |
| `requires.sentinel_contains` | string[]  | no       | `[]`    | If sentinel_files matches, ALSO require one of these regexes in the file content. |

The `requires.tech` and `requires.sentinel_files` gates are unioned
(OR): a matcher runs if either passes. When `requires` is omitted the
matcher always runs.

## Regex flavor

The engine is [`fancy-regex`](https://docs.rs/fancy-regex), which is
mostly Rust's `regex` plus look-around and back-references. Inline
flags (`(?i)`, `(?m)`, `(?s)`) work. Anchors `^`/`$` are line-anchored
when `(?m)` is set.

Tips:

- **Quote backslashes in TOML.** `"\\b"` not `"\b"`.
- **Use `(?i)` for case-insensitive matching** rather than character
  classes.
- **Anchor route-handler matchers** so they don't fire on type imports
  named `app.post`.
- **Pair noisy patterns with `require_content`** so the matcher
  short-circuits on files that don't import the relevant SDK at all.

## Testing matchers

Run the scanner against the planted-vulnerability fixture and
inspect `data/<projectId>/files/`:

```bash
cd /tmp && mkdir t && cd t
cp -R <path-to>/deepsec/fixtures/vulnerable-app ./app
deepsec init --project-id t --root ./app
deepsec scan --project-id t --matchers my-slug
find data/t/files -name '*.json' | xargs grep -l my-slug
```

For finer-grained tests, add a Rust unit test under
`crates/deepsec-scanner/src/matchers.rs#tests` that parses the matcher
inline and calls `matches(content, file_path)`.
