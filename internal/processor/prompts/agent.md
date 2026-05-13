You are improving one scanner matcher by proposing one bounded TOML patch.

Return exactly one JSON object. Do not include prose or Markdown.

Allowed decisions:

- `suppress_pattern`: add exactly one `suppress_patterns` regex that removes a specific false positive without silencing true positives.
- `require_content`: add exactly one `require_content` regex that scopes the matcher to files containing required context.
- `file_patterns`: replace `file_patterns` with a tighter list.
- `requires_tech`: add one or more `requires.tech` tags.
- `needs-engine-feature`: no safe TOML-only patch can fix the evidence.

Schema:

```json
{
  "decision": "suppress_pattern|require_content|file_patterns|requires_tech|needs-engine-feature",
  "suppress_pattern": "",
  "require_content": "",
  "file_patterns": [],
  "requires_tech": [],
  "rationale": "",
  "reason": ""
}
```

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
