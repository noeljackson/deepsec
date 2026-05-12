package processor

// HighlightForTag returns the framework-specific threat context for a
// detected-tech tag, or empty string for unknown tags.
func HighlightForTag(tag string) string {
	switch tag {
	case "nextjs":
		return "Next.js: server actions and route handlers run on the server. Calls into Server Components, server actions, and Route Handlers must check the caller's session — there is no automatic authorization."
	case "express":
		return "Express: middlewares run in order. Auth middleware applied AFTER a route handler does nothing."
	case "fastify":
		return "Fastify: preHandler / preValidation hooks must reject before the route body runs. Decorators set on a request object are not automatically authenticated."
	case "nestjs":
		return "NestJS: AuthGuards must be applied at the controller or method level (UseGuards) AND verified to actually call canActivate."
	case "django":
		return "Django: ORM queries via .raw() or .extra() can be SQL-injectable. `request.GET` / `request.POST` are untrusted. Decorators like @login_required must be present on sensitive views."
	case "fastapi":
		return "FastAPI: Depends() that returns the current user must raise on failure, not return None. Path params bound to Pydantic models are not authorization checks."
	case "flask":
		return "Flask: route functions have no implicit auth. `request.args` / `request.form` are untrusted."
	case "rails":
		return "Rails: `params.permit!` and `params.require(...).permit(...)` patterns are critical. Strong Parameters bypassed = mass assignment."
	case "gin":
		return "Gin: middleware must abort with c.Abort() to block the chain. Reading the request body more than once requires care."
	case "axum":
		return "Axum: extractors run before handlers. Auth extractors must return Result<_, Rejection> and the rejection must be a non-200 response."
	case "actix":
		return "Actix-web: middleware order matters. wrap_fn closures must call .call(req) only after auth succeeds."
	case "docker":
		return "Dockerfile: mutable FROM tags break supply-chain integrity. RUN as root + non-pinned downloads is a remote code execution risk."
	case "github-actions":
		return "GitHub Actions: pull_request_target + checkout of PR head = arbitrary code execution with secrets. Branch protection does not save you here."
	}
	return ""
}

// NoteForSlug returns the per-matcher reasoning hint, or empty string.
func NoteForSlug(slug string) string {
	switch slug {
	case "auth-bypass":
		return "Look for an authentication or authorization check that's been disabled, commented out, or short-circuited via a constant. Confirm the surrounding route is actually reachable."
	case "sql-injection-string-concat":
		return "Verify the input flowing into the query is user-controlled (not a server-side constant). Parameterized callers are safe."
	case "command-injection":
		return "Check whether the user-controlled fragment is shell-quoted, validated against an allowlist, or constrained to a known set of arguments."
	case "ssrf":
		return "Look at whether the URL is validated against an allowlist of hosts and whether the request is made server-side from a privileged network."
	case "path-traversal":
		return "Decide whether normalization (e.g. resolve+startsWith) is applied before the read/write, and whether symlinks are followed."
	case "open-redirect":
		return "Decide whether the redirect target is restricted to same-origin or an allowlist of trusted hosts."
	case "dangerous-html":
		return "Confirm the value reaches the DOM/HTML stream without sanitization (DOMPurify, sanitize-html, framework's safe-by-default escaping)."
	case "cors-wildcard":
		return "Wildcard origin is fine for fully public APIs without credentials. Combined with credentials it leaks authenticated responses to attacker pages."
	case "secret-plaintext":
		return "Confirm it's a real secret (not a placeholder, example, or test value). Decide if it's already revoked."
	case "weak-default-secret":
		return "If the default is used in production (rather than overridden by env var), forged tokens become trivial."
	case "agent-loop-no-cap":
		return "Without a maxSteps / maxTurns / signal cap, prompt injection or adversarial input can DoS the agent or burn unbounded cost."
	case "agentic-untrusted-prompt-input":
		return "Decide whether the user-controlled string is treated as data or instructions. If it can change the agent's behavior, it's prompt-injectable."
	case "mcp-tool-handler":
		return "MCP tools called by an agent inherit the agent's authority. Tool handlers must authorize the caller and validate args."
	case "dockerfile-mutable-tag":
		return "Pinning to a digest (image@sha256:...) prevents supply-chain swaps. `latest` and version-less FROMs reroll on every build."
	case "github-workflow-pwn-request":
		return "pull_request_target runs with the secrets of the target repo. Checking out the PR head means running attacker code with those secrets."
	case "k8s-privileged-pod":
		return "Privileged + hostNetwork is effectively root on the node. Always question whether the workload truly needs it."
	}
	return ""
}
