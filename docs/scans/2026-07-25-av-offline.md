# AV offline credential-broker assessment — 2026-07-25

Target: [`noeljackson/av`](https://github.com/noeljackson/av), initially
assessed at `891477a939c2552791de02d8ef3db96dbeb63ef6` and then retested with
the approved remediation in the target working tree.

The initial assessment was read-only. After review and approval, the one
confirmed high-severity finding was remediated and retested. Deepsec used a
disposable data directory outside the target; the directory was deleted after
each scan. No real credential, Infisical, OpenBao, Zitadel, or external AI
provider was contacted.

## Scope and method

Deepsec scanned 49 eligible files with 130 active matchers. It detected
`axum`, `rust`, `svelte`, `typescript`, `helm`, `docker`, and GitHub Actions.
The initial scan produced 25 review candidates—not 25 vulnerabilities. The
post-remediation scan produced 24; the credential-inheritance pattern no
longer matched. Manual source review then traced each material candidate to its
authorization, configuration, or delivery boundary.

| Boundary | Offline evidence | Assessment result |
|---|---|---|
| Sensitive Axum routes | `src/server.rs` profile-secret and proxy routes | Authentication is performed in each sensitive handler before connector work. |
| OIDC/JWT and JWKS | `src/auth.rs` validation and refresh paths | Allowed asymmetric algorithms, issuer, audience, expiry, `kid`, group checks, and a 60-second unknown-key refresh cooldown are present. |
| Connector/profile delivery | `src/infisical.rs`, `src/openbao.rs`, `src/config.rs` | HTTPS/configured-origin validation, credential-file references, profile key allowlists, scalar-only OpenBao values, and rejection of unmanaged dynamic leases are present. |
| Tier-2 proxy | `src/server.rs`, `src/config.rs` | Fixed upstream origin, method/path/query/content/header allowlists, no redirects, sensitive credential injection, bounded bodies/responses, and response redaction are present. |
| Tier-3 child execution | `src/main.rs` | Direct argv execution is used; no shell is invoked. The child explicitly removes AV wrapper authentication variables after applying profile variables. |
| Helm | `chart/av/templates/deployment.yaml`, `values.yaml` | Restricted pod/container defaults, read-only config/credential mounts, and disabled-by-default ingress were reviewed. |
| Browser/OIDC UI | `ui/src/App.svelte` | Authorization Code + PKCE and state checks are present; access tokens stay in memory rather than durable browser storage. |

## Confirmed finding and remediation

### HIGH — wrapper authentication credentials are inherited by the selected-profile child

`src/main.rs` retrieves a profile using `AV_TOKEN`, or the optional
`AV_BASIC_USER` / `AV_BASIC_PASSWORD`, then starts the requested child with
`ProcessCommand::new(...).args(...).envs(secrets)`. Rust subprocesses inherit
their parent environment unless values are explicitly removed.

Consequently, when the wrapper is authenticated through those environment
variables, the child receives the wrapper's AV authentication credential in
addition to the selected profile's secret set. A compromised child can call AV
for any profile available to that identity rather than remaining limited to the
selected profile. This is especially material where one identity can access
both development and production profiles.

Approved remediation:

```rust
ProcessCommand::new(executable)
    .args(arguments)
    .envs(secrets)
    .env_remove("AV_TOKEN")
    .env_remove("AV_BASIC_USER")
    .env_remove("AV_BASIC_PASSWORD")
```

The removals intentionally follow `envs(secrets)`, so a profile cannot
reintroduce a wrapper credential with a reserved name. A unit regression test
asserts all three variables are absent from the child environment while an
allowlisted profile value remains available. The subsequent offline scan no
longer reports the credential-inheritance candidate.

## Validated mitigations and non-findings

- The proxy does not use an arbitrary caller-supplied destination and removes
  the configured injection header before adding its own sensitive credential.
- Profile-secret responses require authentication and carry `no-store`; logs
  record profile/key count rather than secret values.
- The UI's session storage holds only the temporary PKCE verifier/state and
  removes both after the code exchange. It does not retain the access token.
- Basic authentication validates Argon2id parameters and bounds concurrent
  expensive verification to two jobs with a queue timeout.
- The OpenBao connector explicitly rejects leased/renewable dynamic responses
  until AV can own renewal and revocation.

## Verification performed

All commands below passed against the remediated target working tree:

```text
cargo fmt --all -- --check
cargo test --locked --all-targets        # 24 tests passed
cargo clippy --locked --all-targets -- -D warnings
(cd ui && bun install --frozen-lockfile && bun run check && bun run build)
supplychain ci --policy=strict .
container image scan (fail on high)
helm lint chart/av
connector integration verification       # connector_integration=ok
isolated ZAP runner                      # container exit=0
```

The connector and ZAP verification used fresh, private Docker Compose data for
AV, Infisical, OpenBao, Postgres, Redis, and a test upstream, followed by
container/network/volume teardown.

The UI dependency lock was also regenerated once with Bun's minimum-age gate
temporarily bypassed to resolve the already-disclosed PostCSS advisory. The
repository default remains a 30-day release-age gate and the exact
`postcss@8.5.18` override documents the reviewed exception.

## Residual risks and blind spots

- AV authorization is group-level. It intentionally does not implement
  per-profile or per-route identity grants; deployment configuration therefore
  determines whether development and production profiles share an identity.
- This review did not test the deployed ingress, Zitadel client settings,
  network policy, provider-side authorization, or real provider behavior.
- The external AI investigation phase was intentionally not run. It requires
  separate approval because source is hostile input and may contain material
  unsuitable for an external provider.
- Static candidate detection is not whole-program taint analysis. The
  benchmarks demonstrate the curated high/critical patterns, not universal
  vulnerability absence.

## Result

One confirmed high-severity issue was fixed and regression-tested. No other
confirmed high or critical findings remain from the offline assessment. The
coverage and residual-risk boundaries above still apply.
