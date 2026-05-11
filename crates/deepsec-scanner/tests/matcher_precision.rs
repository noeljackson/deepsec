//! Precision tests for the bundled matcher pack. For each
//! security-relevant matcher we assert that representative POSITIVE
//! samples produce a hit and representative NEGATIVE samples don't.

use deepsec_scanner::{Matcher, MatcherRegistry};

fn registry() -> MatcherRegistry {
    MatcherRegistry::with_builtin().expect("builtin matchers compile")
}

fn matcher_for<'a>(reg: &'a MatcherRegistry, slug: &str) -> &'a Matcher {
    reg.get(slug).unwrap_or_else(|| panic!("missing slug: {slug}"))
}

fn assert_hits(m: &Matcher, content: &str, file: &str) {
    let hits = m.matches(content, file);
    assert!(
        !hits.is_empty(),
        "expected hit on {file} for {}; content was:\n{content}",
        m.slug()
    );
}

fn assert_no_hits(m: &Matcher, content: &str, file: &str) {
    let hits = m.matches(content, file);
    assert!(
        hits.is_empty(),
        "expected NO hit on {file} for {}; got {} hits",
        m.slug(),
        hits.len()
    );
}

#[test]
fn sql_injection_detects_interpolated_query() {
    let r = registry();
    let m = matcher_for(&r, "sql-injection-string-concat");
    assert_hits(
        m,
        r#"const rows = db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);"#,
        "src/api/users.ts",
    );
    assert_hits(
        m,
        r#"cursor.execute(f"SELECT * FROM users WHERE id = {request.args['id']}")"#,
        "app/views.py",
    );
}

#[test]
fn sql_injection_skips_parameterized_query() {
    let r = registry();
    let m = matcher_for(&r, "sql-injection-string-concat");
    assert_no_hits(
        m,
        r#"const rows = db.query("SELECT * FROM users WHERE id = ?", [id]);"#,
        "src/api/users.ts",
    );
}

#[test]
fn command_injection_detects_shell_true() {
    let r = registry();
    let m = matcher_for(&r, "command-injection");
    assert_hits(
        m,
        "subprocess.run(['bash', '-c', cmd], shell=True)",
        "scripts/run.py",
    );
    assert_hits(
        m,
        r#"const out = execSync(`tar -xf ${req.body.name}`);"#,
        "src/upload.ts",
    );
}

#[test]
fn command_injection_skips_static_argv() {
    let r = registry();
    let m = matcher_for(&r, "command-injection");
    assert_no_hits(
        m,
        r#"subprocess.run(["ls", "-la"], check=True)"#,
        "scripts/run.py",
    );
}

#[test]
fn ssrf_detects_user_url_to_fetch() {
    let r = registry();
    let m = matcher_for(&r, "ssrf");
    assert_hits(
        m,
        "const data = await fetch(req.body.targetUrl);",
        "src/proxy.ts",
    );
    assert_hits(
        m,
        "const u = new URL(query.dest);\nconst r = await fetch(u);",
        "src/proxy.ts",
    );
}

#[test]
fn ssrf_skips_constant_url() {
    let r = registry();
    let m = matcher_for(&r, "ssrf");
    assert_no_hits(
        m,
        "const data = await fetch('https://api.example.com/health');",
        "src/health.ts",
    );
}

#[test]
fn path_traversal_detects_user_path_to_read() {
    let r = registry();
    let m = matcher_for(&r, "path-traversal");
    assert_hits(
        m,
        "const buf = fs.readFileSync(req.params.path);",
        "src/api/download.ts",
    );
    assert_hits(
        m,
        "const f = path.join('/uploads', body.name);",
        "src/api/upload.ts",
    );
}

#[test]
fn open_redirect_detects_user_redirect() {
    let r = registry();
    let m = matcher_for(&r, "open-redirect");
    assert_hits(
        m,
        "res.redirect(req.query.next);",
        "src/auth/callback.ts",
    );
}

#[test]
fn dangerous_html_detects_react_pattern() {
    let r = registry();
    let m = matcher_for(&r, "dangerous-html");
    assert_hits(
        m,
        r#"return <div dangerouslySetInnerHTML={{ __html: comment.body }} />;"#,
        "src/components/comment.tsx",
    );
}

#[test]
fn dangerous_html_skips_safe_jsx() {
    let r = registry();
    let m = matcher_for(&r, "dangerous-html");
    assert_no_hits(
        m,
        r#"return <p>{comment.body}</p>;"#,
        "src/components/comment.tsx",
    );
}

#[test]
fn cors_wildcard_detects_credentialed_wildcard() {
    let r = registry();
    let m = matcher_for(&r, "cors-wildcard");
    assert_hits(
        m,
        r#"app.use(cors({ origin: "*", credentials: true }));"#,
        "src/server.ts",
    );
    assert_hits(
        m,
        r#"res.setHeader("Access-Control-Allow-Origin", "*");"#,
        "src/server.ts",
    );
}

#[test]
fn dev_auth_bypass_detects_env_gated_skip() {
    let r = registry();
    let m = matcher_for(&r, "dev-auth-bypass");
    assert_hits(
        m,
        "if (process.env.NODE_ENV !== 'production') { return next(); }",
        "src/middleware/auth.ts",
    );
}

#[test]
fn debug_endpoint_detects_django_debug() {
    let r = registry();
    let m = matcher_for(&r, "debug-endpoint");
    assert_hits(m, "DEBUG = True", "settings.py");
}

#[test]
fn secret_plaintext_detects_aws_key_format() {
    let r = registry();
    let m = matcher_for(&r, "secret-plaintext");
    assert_hits(
        m,
        r#"const AWS_ACCESS_KEY_ID = "AKIAQRSTUVWXYZ012345";"#,
        "src/config.ts",
    );
    assert_hits(
        m,
        r#"const GITHUB_TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";"#,
        "src/config.ts",
    );
}

#[test]
fn secret_plaintext_skips_obvious_placeholder() {
    let r = registry();
    let m = matcher_for(&r, "secret-plaintext");
    // Suppression keyword: EXAMPLE/PLACEHOLDER/REPLACE_ME/YOUR_KEY
    // The matcher's suppress_patterns scans the snippet window, not the
    // pattern itself, so we craft a snippet that contains "EXAMPLE".
    assert_no_hits(
        m,
        "// EXAMPLE config value, replace before deploy\nconst k = \"sk-EXAMPLE-not-a-real-key\";",
        "src/config.ts",
    );
}

#[test]
fn weak_default_secret_detects_jwt_dev_default() {
    let r = registry();
    let m = matcher_for(&r, "weak-default-secret");
    assert_hits(
        m,
        r#"const JWT_SECRET = "dev";"#,
        "src/config.ts",
    );
}

#[test]
fn insecure_crypto_detects_md5() {
    let r = registry();
    let m = matcher_for(&r, "insecure-crypto");
    assert_hits(
        m,
        r#"const h = crypto.createHash("md5").update(password).digest("hex");"#,
        "src/lib/hash.ts",
    );
    assert_hits(
        m,
        "import hashlib\nh = hashlib.md5(password.encode()).hexdigest()",
        "src/lib/hash.py",
    );
}

#[test]
fn insecure_crypto_skips_sha256() {
    let r = registry();
    let m = matcher_for(&r, "insecure-crypto");
    assert_no_hits(
        m,
        r#"const h = crypto.createHash("sha256").update(p).digest();"#,
        "src/lib/hash.ts",
    );
}

#[test]
fn algorithm_confusion_detects_alg_none() {
    let r = registry();
    let m = matcher_for(&r, "algorithm-confusion");
    assert_hits(
        m,
        r#"jwt.verify(token, secret, { algorithms: ["none"] });"#,
        "src/auth.ts",
    );
}

#[test]
fn agent_loop_no_cap_detects_uncapped_stream_text() {
    let r = registry();
    let m = matcher_for(&r, "agent-loop-no-cap");
    assert_hits(
        m,
        r#"import { streamText } from "ai";
const result = streamText({
  model: openai("gpt-4"),
  prompt: userInput,
});"#,
        "src/agent.ts",
    );
}

#[test]
fn agent_loop_no_cap_skips_capped_call() {
    let r = registry();
    let m = matcher_for(&r, "agent-loop-no-cap");
    assert_no_hits(
        m,
        r#"import { streamText } from "ai";
const result = streamText({
  model: openai("gpt-4"),
  prompt: userInput,
  maxSteps: 5,
});"#,
        "src/agent.ts",
    );
}

#[test]
fn tls_skip_verification_detects_node_reject_unauthorized() {
    let r = registry();
    let m = matcher_for(&r, "tls-skip-verification");
    assert_hits(
        m,
        "const agent = new https.Agent({ rejectUnauthorized: false });",
        "src/http.ts",
    );
}

#[test]
fn dockerfile_mutable_tag_detects_latest() {
    let r = registry();
    let m = matcher_for(&r, "dockerfile-mutable-tag");
    assert_hits(m, "FROM node:latest\nRUN echo hi", "Dockerfile");
}

#[test]
fn dockerfile_mutable_tag_skips_pinned() {
    let r = registry();
    let m = matcher_for(&r, "dockerfile-mutable-tag");
    assert_no_hits(
        m,
        "FROM node:22.5.0-alpine3.20\nRUN echo hi",
        "Dockerfile",
    );
}

#[test]
fn terraform_iam_wildcard_detects() {
    let r = registry();
    let m = matcher_for(&r, "terraform-iam-wildcard");
    assert_hits(
        m,
        r#"resource "aws_iam_policy" "x" {
  policy = jsonencode({
    Statement = [{
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }]
  })
}"#,
        "iam.tf",
    );
}

#[test]
fn registry_apply_filter_only_keeps_listed() {
    let mut r = registry();
    r.apply_filter(&["auth-bypass".into()], &[]);
    assert_eq!(r.len(), 1);
    assert!(r.get("auth-bypass").is_some());
}

#[test]
fn registry_apply_filter_exclude_drops_listed() {
    let mut r = registry();
    let before = r.len();
    r.apply_filter(&[], &["auth-bypass".into()]);
    assert_eq!(r.len(), before - 1);
    assert!(r.get("auth-bypass").is_none());
}

#[test]
fn snippet_window_is_built_correctly() {
    let r = registry();
    let m = matcher_for(&r, "command-injection");
    let body = "// line 1\n// line 2\nsubprocess.run(['x'], shell=True)\n// line 4\n// line 5\n// line 6\n// line 7\n";
    let hits = m.matches(body, "test.py");
    assert_eq!(hits.len(), 1);
    let h = &hits[0];
    assert_eq!(h.line_numbers, vec![3]);
    // snippet_before defaults to 1 (line 2) and snippet_after defaults to
    // 5 (lines 4-8). Verify both bounds.
    assert!(h.snippet.contains("// line 2"));
    assert!(h.snippet.contains("subprocess.run"));
    assert!(h.snippet.contains("// line 4"));
}
