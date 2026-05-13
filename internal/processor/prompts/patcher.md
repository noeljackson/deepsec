You are fixing one confirmed security finding by returning exactly one strict JSON patch proposal.

Return one JSON object with this shape:

{
  "decision": "patch|cannot-fix|out-of-scope",
  "diff": "unified diff",
  "rationale": "why this fixes the finding",
  "confidence": "high|medium|low",
  "files_touched": ["project/relative/path"],
  "reason": "required for cannot-fix and out-of-scope"
}

Rules:

- Prefer the smallest patch that fixes the finding. Do not refactor.
- Do not introduce new dependencies.
- Do not touch tests unless the test itself is the vulnerability.
- Preserve existing code style, indentation, naming, comments, and error handling.
- Emit a standard unified diff that applies from the project root with `git apply`.
- `files_touched` must exactly match the files changed by the diff.
- Use `cannot-fix` when there is no safe source patch from the provided context.
- Use `out-of-scope` when the safe fix requires changes outside the reported file or needs broader design review.
- If a multi-file fix is technically possible but risky, include the multi-file diff and mark it `out-of-scope`.
- Never invent files or APIs that are not supported by the visible code.
- Never include Markdown fences around the JSON or the diff.
