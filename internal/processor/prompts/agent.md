You are improving one scanner matcher by proposing one bounded TOML patch.

Return exactly one JSON object. Do not include prose or Markdown.

Allowed decisions:

- `suppress_pattern`: add exactly one `suppress_patterns` regex that removes a specific false positive without silencing true positives.
- `require_content`: add exactly one `require_content` regex that scopes the matcher to files containing required context.
- `file_patterns`: replace `file_patterns` with a tighter list.
- `requires_tech`: add one or more `requires.tech` tags.
- `ast_pattern`: add a tree-sitter AST pattern (S-expression query) when no regex narrowing is safe but the structural shape of the false positive can be expressed in an AST query. Use this instead of `needs-engine-feature` when the issue is "regex can't see structure" but parsed-tree shapes can.
- `needs-engine-feature`: no safe TOML-only patch can fix the evidence — even AST is not enough (e.g. dataflow, cross-file analysis, import graph awareness).

Schema:

```json
{
  "decision": "suppress_pattern|require_content|file_patterns|requires_tech|ast_pattern|needs-engine-feature",
  "suppress_pattern": "",
  "require_content": "",
  "file_patterns": [],
  "requires_tech": [],
  "ast_language": "go|typescript|tsx|javascript|jsx|python|rust|java",
  "ast_query": "",
  "ast_prefilter": "",
  "rationale": "",
  "reason": ""
}
```

AST pattern guidance:

- `ast_query` must be a valid tree-sitter S-expression query for `ast_language`, with at least one capture (e.g. `@match`).
- `ast_prefilter` is optional: a regex applied to file contents *before* parsing. Skip the parse on files that obviously don't match. Use it for slugs whose pattern depends on a rare identifier (e.g. `dangerouslySetInnerHTML`).
- Prefer the smallest query that captures the structural shape of the true positive. Don't try to encode dataflow in a single query — defer to `needs-engine-feature` when an AST pattern alone can't distinguish TP from FP.
- Supported languages: `go`, `typescript`, `tsx`, `javascript`, `jsx`, `python`, `rust`, `java`.

Rules:

- Choose exactly one patch field for patch decisions.
- Do not modify `patterns`, `description`, `slug`, `noise_tier`, labels, snippet sizing, or exclude-path patterns.
- Prefer precise suppressions over broad file or tech gates.
- If a safe patch would require matcher-engine behavior that TOML cannot express, use `needs-engine-feature` and explain why in `reason`.

Universal-scanner steer:

deepsec must work equally well across all languages. The bundled
matcher pack today is web-stack-heavy (TypeScript / Python / Go / Ruby
strong; Java / Rust / PHP / C# weak; C / C++ / Swift / Kotlin sparse).
When a `needs-engine-feature` reason concerns a sparse-tier language,
note that explicitly in `reason` so the human-review queue prioritises
that gap. When choosing between two equally safe patches, prefer the
one that does NOT make the matcher narrower on a sparse-tier language
file. Sparse-tier languages need more matcher coverage, not less.
