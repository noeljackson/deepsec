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
