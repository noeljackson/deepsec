# Patch generation

`deepsec patch` turns an existing finding into a proposed source diff.
The command never edits the configured project root during proposal or
validation. It materializes a throwaway clone/copy, runs `git apply
--check`, applies the diff, runs the requested validation command, and
only then persists provenance.

## Usage

Patch one finding:

```bash
deepsec patch --project-id myproj --finding-id <id> --validate "go test ./..."
```

Patch a bounded set selected from the latest stored findings:

```bash
deepsec patch --project-id myproj --since-run <run-id> --max-per-run 3
deepsec patch --project-id myproj --severity HIGH,CRITICAL --slug ssrf
```

Dry-run is the default. On a validated dry-run, deepsec writes:

```text
data/<projectId>/patches/<finding-id>.patch.json
PATCH_DECISIONS.md
```

`PATCH_DECISIONS.md` is local and gitignored. The JSON file records the
decision, unified diff, touched files, provider/model/settings, usage,
cost, validation command, validation exit code, stdout/stderr tails, and
the commit hash when one was created.

## Apply and push

`--apply` requires a clean git tree in the target project. It creates a
branch named:

```text
deepsec-patch/<finding-id>
```

and commits with a structured message containing the finding id, project
id, reported file, slug, confidence, and rationale.

`--push` requires `--apply`. It pushes the branch and runs:

```bash
gh pr create --fill
```

## Validation

`--validate "<command>"` runs in the sandbox after the diff is applied.
Use the project's normal focused gate, for example:

```bash
deepsec patch --project-id api --finding-id <id> --validate "go test ./..."
deepsec patch --project-id web --finding-id <id> --validate "pnpm test"
```

If `--validate` is omitted, validation is marked as skipped in both the
console output and provenance. The timeout defaults to five minutes and
can be changed with `--validation-timeout`.

## JSON schema

The patcher returns strict JSON. Unknown fields are rejected.

```json
{
  "decision": "patch|cannot-fix|out-of-scope",
  "diff": "...unified diff...",
  "rationale": "...",
  "confidence": "high|medium|low",
  "files_touched": ["src/lib/foo.ts"],
  "reason": "required for cannot-fix and out-of-scope"
}
```

`files_touched` must exactly match the files in the unified diff.
`cannot-fix` and `out-of-scope` are logged for human review and do not
write patch JSON. A diff touching anything outside the finding's reported
file is forced to `out-of-scope`.

## Safety rails

- The configured project root is never modified during dry-run.
- `--apply` and `--push` require a clean target git tree.
- `--push` is refused unless `--apply` is set.
- Validation failures do not write patch JSON and leave the target tree
  untouched.
- The command refuses to patch the deepsec repository itself.
- No new dependencies are introduced by the patcher prompt; source
  changes should be minimal and style-preserving.

## Compliance follow-up

Patch provenance is designed to feed compliance reporting. A follow-up
can copy a successful patch commit hash into the compliance manifest as
`verified_fix_commit`.
