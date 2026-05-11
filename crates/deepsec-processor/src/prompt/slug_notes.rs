/// Per-matcher reasoning hint surfaced in the prompt context.
pub fn note_for_slug(slug: &str) -> Option<&'static str> {
    Some(match slug {
        "auth-bypass" => "Look for an authentication or authorization check that's been disabled, commented out, or short-circuited via a constant. Confirm the surrounding route is actually reachable.",
        "sql-injection-string-concat" => "Verify the input flowing into the query is user-controlled (not a server-side constant). Parameterized callers are safe.",
        "command-injection" => "Check whether the user-controlled fragment is shell-quoted, validated against an allowlist, or constrained to a known set of arguments.",
        "ssrf" => "Look at whether the URL is validated against an allowlist of hosts and whether the request is made server-side from a privileged network.",
        "path-traversal" => "Decide whether normalization (e.g. resolve+startsWith) is applied before the read/write, and whether symlinks are followed.",
        "open-redirect" => "Decide whether the redirect target is restricted to same-origin or an allowlist of trusted hosts.",
        "dangerous-html" => "Confirm the value reaches the DOM/HTML stream without sanitization (DOMPurify, sanitize-html, framework's safe-by-default escaping).",
        "cors-wildcard" => "Wildcard origin is fine for fully public APIs without credentials. Combined with credentials it leaks authenticated responses to attacker pages.",
        "secret-plaintext" => "Confirm it's a real secret (not a placeholder, example, or test value). Decide if it's already revoked.",
        "weak-default-secret" => "If the default is used in production (rather than overridden by env var), forged tokens become trivial.",
        "agent-loop-no-cap" => "Without a maxSteps / maxTurns / signal cap, prompt injection or adversarial input can DoS the agent or burn unbounded cost.",
        "agentic-untrusted-prompt-input" => "Decide whether the user-controlled string is treated as data or instructions. If it can change the agent's behavior, it's prompt-injectable.",
        "mcp-tool-handler" => "MCP tools called by an agent inherit the agent's authority. Tool handlers must authorize the caller and validate args.",
        "dockerfile-mutable-tag" => "Pinning to a digest (image@sha256:...) prevents supply-chain swaps. `latest` and version-less FROMs reroll on every build.",
        "github-workflow-pwn-request" => "pull_request_target runs with the secrets of the target repo. Checking out the PR head means running attacker code with those secrets.",
        "k8s-privileged-pod" => "Privileged + hostNetwork is effectively root on the node. Always question whether the workload truly needs it.",
        _ => return None,
    })
}
