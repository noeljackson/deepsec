# Acme inventory webapp

A Next.js 15 monorepo for an internal inventory + procurement webapp.
~150k LOC. Backend API in `src/api/`, server-only library in
`src/lib/`, admin tools under `src/api/admin/` and `src/app/admin/`,
billing in `src/api/billing/`. Postgres via Drizzle, Stripe for
subscriptions, Auth.js (NextAuth v5) for authentication, custom
`auth.has(actor, action, resource)` helper for authorization.

## Auth shape

- **Authentication**: Auth.js with email magic-link + GitHub OAuth.
  `getServerSession(req)` returns `{ user: { id, email, role } | null }`.
  `req.session` is the same shape, attached by middleware.
- **Authorization**: every API handler MUST call
  `auth.has(req.session.user, action, resource)` before mutating or
  reading sensitive data. Never `req.session.user.role === "admin"`
  directly — that's a code smell.
- **Rate limiting**: every public handler wraps with
  `withRateLimit(handler, { window: "1m", max: 60 })`. Internal-only
  routes under `src/api/_internal/` skip rate limiting (private VPC).
  Webhook receivers under `src/api/webhooks/` use signature verification
  instead and skip rate limiting.

## Threat model

The webapp holds inventory data, supplier credentials (encrypted),
purchase orders, and billing details. The most attractive attacks:

1. **Cross-tenant access** — every record has a `companyId` and a
   `userId`. A handler that reads/writes by `id` without filtering by
   `req.session.user.companyId` is an IDOR.
2. **Privilege escalation** — flipping a non-admin user to admin via
   the user-update endpoints. Look for `role` field assignments outside
   of `src/api/admin/users/promote.ts`.
3. **Stripe webhook replay / forgery** — `src/api/webhooks/stripe.ts`
   verifies signatures. Any handler that processes Stripe events
   without `verifyStripeSignature(req)` is suspect.
4. **Supplier credential exfiltration** — credentials are encrypted at
   rest with `vault.encrypt(value, { context })`. Decryption sites that
   omit context, log decrypted values, or return them in API responses
   are critical.
5. **Debug-flag bypasses** — staging and preview deploys occasionally
   set `NODE_ENV !== "production"`, which unlocks endpoints like
   `/api/_dev/dump-cache`. Real production should never expose those
   even when the flag is unset incorrectly.

## False-positive sources to ignore

- `src/scripts/migrations/**` — one-shot migrations run via
  `tsx scripts/migrations/<file>.ts`. They legitimately read/write
  across tenants because they're admin-run.
- `src/lib/seed/**` — DB seed data, dev-only.
- Any file under `__tests__/` or matching `*.test.ts` / `*.spec.ts`.
- `src/api/_internal/health.ts` — private health endpoint, no auth on
  purpose (private VPC, behind service mesh).

## Conventions worth knowing

- Drizzle queries use the `db.query.<table>.findFirst({ where, with })`
  builder. `db.execute(sql\`...\`)` is forbidden by lint; flag any.
- The custom `safeRedirect(targetUrl)` helper guards against open
  redirects by checking against an `ALLOWED_HOSTS` list. Any redirect
  that doesn't go through `safeRedirect` is an open-redirect candidate.
- Server actions live in `src/actions/`. They start with `"use server"`
  and must call `auth.has(...)` like API routes.
