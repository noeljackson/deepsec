// Minimal repro of an open redirect on the post-login flow.
// Pattern derived from a real HIGH Codex Cyber finding.
//
// The vulnerability: the login route accepts a `return_to` query
// parameter without validation and assigns it directly to
// `window.location.href` after a successful sign-in. An attacker can
// craft a login URL with `return_to=https://evil.example` for
// phishing redirects, or `return_to=javascript:…` for XSS in the
// dashboard origin running as the freshly-authenticated user.

import { useState } from "react";

type SearchParams = {
  return_to?: string;
  authRequestID?: string;
};

function vulnerableLogin(search: SearchParams) {
  // ...sign-in happens here...

  if (search.return_to) {
    // BUG: unvalidated user-controlled URL assigned to window.location.
    window.location.href = search.return_to;
    return;
  }
  window.location.href = "/dashboard";
}

function safeLogin(search: SearchParams) {
  // ...sign-in happens here...
  const candidate = search.return_to ?? "/dashboard";
  // Allowlist: only same-origin relative paths.
  if (!/^\/[a-zA-Z0-9_\-/?=&%.]*$/.test(candidate)) {
    window.location.href = "/dashboard";
    return;
  }
  window.location.href = candidate;
}

export { vulnerableLogin, safeLogin };
