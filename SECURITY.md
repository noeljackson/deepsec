# Security policy

deepsec is a security tool. We take vulnerabilities **in deepsec
itself** seriously and ask that you give us a chance to fix them
before they become public.

## Reporting

For vulnerabilities in deepsec — the scanner engine, the AI
investigation pipeline, the bundled matcher pack, the AST bridge, the
compliance reporter, or any first-party CLI — please **do not open a
public GitHub issue**. Instead, use one of:

- **GitHub Security Advisories** (preferred):
  https://github.com/noeljackson/deepsec/security/advisories/new
- **Email**: `security@noeljackson.com`

PGP available on request.

Include:

- A minimal reproduction (a single command, a fixture file, or a
  patch is ideal).
- Affected versions / commits — `deepsec --version` plus the
  branch/tag.
- Your assessment of severity and blast radius.
- Whether you've already disclosed publicly anywhere (please don't,
  but we want to know if you have).

## What's in scope

Vulnerabilities in the deepsec project itself:

- **CLI / engine**: command injection, path traversal, or unsafe
  deserialization in deepsec's own code paths.
- **Matcher engine**: a malicious matcher TOML that escapes into
  arbitrary code execution, sandbox escape, or denial-of-service
  against the scanner.
- **AI backends**: prompt injection that exfiltrates project source
  beyond the configured backend, or that causes deepsec to take
  destructive actions outside the user's scope.
- **AST bridge** (wazero / tree-sitter WASM loading): a crafted
  grammar that escapes the wazero sandbox.
- **Compliance reports**: signed-manifest forgery, signature
  downgrade, or HMAC key extraction.
- **CI integrations**: pre-commit hook or GitHub Action that leaks
  the scanned repo's secrets via deepsec's own action.

## What's out of scope

- **Vulnerabilities deepsec finds in user code**. That's the product
  working — file a GitHub issue or follow the user's own security
  channel.
- **Vulnerabilities in upstream Go modules**, `tree-sitter-*` npm
  packages, wazero, or other dependencies. Please file them upstream;
  we'll pick up the fix on the next bump.
- **Misconfiguration of deepsec by the user** (API keys leaked into
  logs, public CI output, etc.). The product can help mitigate via
  `--max-cost-usd`, `--record`, sensitive-log matchers — but the
  responsibility is the user's.
- **DoS via expensive AI calls**. Already addressed by
  `--max-cost-usd` and `deepsec spend` — file a feature issue if you
  want stronger controls.

## Triage and disclosure

- **Acknowledgement**: within 3 business days.
- **Initial triage**: within 7 business days.
- **Fix or workaround**: depends on severity. Critical vulns get an
  out-of-band patch release; high/medium go into the next regular
  release; low get a normal-priority PR.
- **Disclosure**: coordinated. Once a fix is shipped and most users
  have had time to update (typically 30 days), the GitHub Security
  Advisory becomes public. Reporters are credited unless they prefer
  otherwise.

## Threat model

The short version: deepsec is run **by a developer or CI bot, against
source code that may be untrusted, calling out to an LLM provider
the user configures.** The trust boundaries:

| Boundary | Assumption |
|----------|------------|
| Project source | **Untrusted-shape** — deepsec must read it without executing it. Matchers run regex + tree-sitter parsing over file bytes; no code from the project is executed. |
| Matcher pack | **Trusted** if bundled. The user can supply `[matchers].extra_paths` for custom matchers; those are author-trusted. The matcher engine never executes user-supplied code (TOML schema is strict + compiled to RE2 / tree-sitter queries). |
| AI provider | **Trusted to operate** but **not trusted to be private** — the user opted in. deepsec sends source snippets + prompts to whichever backend is configured. The skeptic / patch / report agents likewise. |
| Filesystem | deepsec writes to `data/<projectId>/` and report output paths. `AssertSafeFilePath` / `AssertSafeSegment` gate every write. |
| Network | Only AI provider endpoints are contacted (HTTPS, host-pinned per provider profile). No telemetry, no analytics, no auto-update. |
| Compliance manifest | HMAC-signed with `DEEPSEC_REPORT_SIGNING_KEY`. Manifest tampering is detectable via `deepsec report --verify`. Key rotation is the user's responsibility. |

A fuller threat-model document lives at `docs/threat-model.md` (TBD,
issue #94 follow-up).

## Hall of fame

(Will list reporters of accepted vulns once we have any. None yet.)
