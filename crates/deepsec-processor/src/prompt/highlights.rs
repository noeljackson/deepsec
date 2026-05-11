/// Framework-specific threat highlights, keyed by detect-tech tag.
pub fn highlight_for_tag(tag: &str) -> Option<&'static str> {
    Some(match tag {
        "nextjs" => "Next.js: server actions and route handlers run on the server. Calls into Server Components, server actions, and Route Handlers must check the caller's session — there is no automatic authorization.",
        "express" => "Express: middlewares run in order. Auth middleware applied AFTER a route handler does nothing.",
        "fastify" => "Fastify: preHandler / preValidation hooks must reject before the route body runs. Decorators set on a request object are not automatically authenticated.",
        "nestjs" => "NestJS: AuthGuards must be applied at the controller or method level (UseGuards) AND verified to actually call canActivate.",
        "django" => "Django: ORM queries via .raw() or .extra() can be SQL-injectable. `request.GET` / `request.POST` are untrusted. Decorators like @login_required must be present on sensitive views.",
        "fastapi" => "FastAPI: Depends() that returns the current user must raise on failure, not return None. Path params bound to Pydantic models are not authorization checks.",
        "flask" => "Flask: route functions have no implicit auth. `request.args` / `request.form` are untrusted.",
        "rails" => "Rails: `params.permit!` and `params.require(...).permit(...)` patterns are critical. Strong Parameters bypassed = mass assignment.",
        "gin" => "Gin: middleware must abort with c.Abort() to block the chain. Reading the request body more than once requires care.",
        "axum" => "Axum: extractors run before handlers. Auth extractors must return Result<_, Rejection> and the rejection must be a non-200 response.",
        "actix" => "Actix-web: middleware order matters. wrap_fn closures must call .call(req) only after auth succeeds.",
        "docker" => "Dockerfile: mutable FROM tags break supply-chain integrity. RUN as root + non-pinned downloads is a remote code execution risk.",
        "github-actions" => "GitHub Actions: pull_request_target + checkout of PR head = arbitrary code execution with secrets. Branch protection does not save you here.",
        _ => return None,
    })
}
