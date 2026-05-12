package scanner

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func registry(t *testing.T) *Registry {
	t.Helper()
	r, err := WithBuiltin()
	require.NoError(t, err)
	return r
}

func assertHits(t *testing.T, slug string, content, file string) {
	t.Helper()
	r := registry(t)
	m := r.Get(slug)
	require.NotNilf(t, m, "missing matcher: %s", slug)
	hits := m.Match(content, file)
	require.NotEmpty(t, hits, "expected %s to fire on %s", slug, file)
}

func assertNoHits(t *testing.T, slug string, content, file string) {
	t.Helper()
	r := registry(t)
	m := r.Get(slug)
	require.NotNilf(t, m, "missing matcher: %s", slug)
	hits := m.Match(content, file)
	require.Emptyf(t, hits, "expected %s NOT to fire on %s; got %d hits", slug, file, len(hits))
}

func TestBuiltinMatchersCompile(t *testing.T) {
	r, err := WithBuiltin()
	require.NoError(t, err)
	require.GreaterOrEqual(t, r.Len(), 70, "expected at least 70 matchers, got %d", r.Len())
}

func TestSQLInjectionDetectsInterpolatedQuery(t *testing.T) {
	assertHits(t, "sql-injection-string-concat",
		"const rows = db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);",
		"src/api/users.ts")
	assertHits(t, "sql-injection-string-concat",
		`cursor.execute(f"SELECT * FROM users WHERE id = {request.args['id']}")`,
		"app/views.py")
}

func TestSQLInjectionSkipsParameterized(t *testing.T) {
	assertNoHits(t, "sql-injection-string-concat",
		`const rows = db.query("SELECT * FROM users WHERE id = ?", [id]);`,
		"src/api/users.ts")
}

func TestCommandInjectionDetectsShellTrue(t *testing.T) {
	assertHits(t, "command-injection",
		"subprocess.run(['bash', '-c', cmd], shell=True)",
		"scripts/run.py")
	assertHits(t, "command-injection",
		"const out = execSync(`tar -xf ${req.body.name}`);",
		"src/upload.ts")
}

func TestCommandInjectionSkipsStaticArgv(t *testing.T) {
	assertNoHits(t, "command-injection",
		`subprocess.run(["ls", "-la"], check=True)`,
		"scripts/run.py")
}

func TestSSRFDetectsUserURL(t *testing.T) {
	assertHits(t, "ssrf",
		"const data = await fetch(req.body.targetUrl);",
		"src/proxy.ts")
}

func TestSSRFSkipsConstant(t *testing.T) {
	assertNoHits(t, "ssrf",
		"const data = await fetch('https://api.example.com/health');",
		"src/health.ts")
}

func TestPathTraversalDetectsUserPathToRead(t *testing.T) {
	assertHits(t, "path-traversal",
		"const buf = fs.readFileSync(req.params.path);",
		"src/api/download.ts")
}

func TestOpenRedirectDetects(t *testing.T) {
	assertHits(t, "open-redirect",
		"res.redirect(req.query.next);",
		"src/auth/callback.ts")
}

func TestDangerousHTMLDetectsReactPattern(t *testing.T) {
	assertHits(t, "dangerous-html",
		`return <div dangerouslySetInnerHTML={{ __html: comment.body }} />;`,
		"src/components/comment.tsx")
}

func TestDangerousHTMLSkipsSafeJSX(t *testing.T) {
	assertNoHits(t, "dangerous-html",
		`return <p>{comment.body}</p>;`,
		"src/components/comment.tsx")
}

func TestCORSWildcardDetectsCredentialedWildcard(t *testing.T) {
	assertHits(t, "cors-wildcard",
		`app.use(cors({ origin: "*", credentials: true }));`,
		"src/server.ts")
}

func TestSecretPlaintextDetectsKeys(t *testing.T) {
	assertHits(t, "secret-plaintext",
		`const AWS_ACCESS_KEY_ID = "AKIAQRSTUVWXYZ012345";`,
		"src/config.ts")
	assertHits(t, "secret-plaintext",
		`const GITHUB_TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";`,
		"src/config.ts")
}

func TestSecretPlaintextSuppressesPlaceholder(t *testing.T) {
	assertNoHits(t, "secret-plaintext",
		"// EXAMPLE config value, replace before deploy\nconst k = \"sk-EXAMPLE-not-a-real-key\";",
		"src/config.ts")
}

func TestInsecureCryptoDetectsMD5(t *testing.T) {
	assertHits(t, "insecure-crypto",
		`const h = crypto.createHash("md5").update(password).digest("hex");`,
		"src/lib/hash.ts")
	assertHits(t, "insecure-crypto",
		"import hashlib\nh = hashlib.md5(password.encode()).hexdigest()",
		"src/lib/hash.py")
}

func TestInsecureCryptoSkipsSHA256(t *testing.T) {
	assertNoHits(t, "insecure-crypto",
		`const h = crypto.createHash("sha256").update(p).digest();`,
		"src/lib/hash.ts")
}

func TestAlgorithmConfusionDetectsAlgNone(t *testing.T) {
	assertHits(t, "algorithm-confusion",
		`jwt.verify(token, secret, { algorithms: ["none"] });`,
		"src/auth.ts")
}

func TestAgentLoopNoCapDetectsUncapped(t *testing.T) {
	assertHits(t, "agent-loop-no-cap",
		`import { streamText } from "ai";
const result = streamText({
  model: openai("gpt-4"),
  prompt: userInput,
});`,
		"src/agent.ts")
}

func TestAgentLoopNoCapSkipsCapped(t *testing.T) {
	assertNoHits(t, "agent-loop-no-cap",
		`import { streamText } from "ai";
const result = streamText({
  model: openai("gpt-4"),
  prompt: userInput,
  maxSteps: 5,
});`,
		"src/agent.ts")
}

func TestTLSSkipVerifyDetectsRejectUnauthorized(t *testing.T) {
	assertHits(t, "tls-skip-verification",
		"const agent = new https.Agent({ rejectUnauthorized: false });",
		"src/http.ts")
}

func TestDockerfileMutableTagDetectsLatest(t *testing.T) {
	assertHits(t, "dockerfile-mutable-tag",
		"FROM node:latest\nRUN echo hi",
		"Dockerfile")
}

func TestDockerfileMutableTagSkipsPinned(t *testing.T) {
	assertNoHits(t, "dockerfile-mutable-tag",
		"FROM node:22.5.0-alpine3.20\nRUN echo hi",
		"Dockerfile")
}

func TestRegistryApplyFilterOnly(t *testing.T) {
	r := registry(t)
	r.ApplyFilter([]string{"auth-bypass"}, nil)
	require.Equal(t, 1, r.Len())
	require.NotNil(t, r.Get("auth-bypass"))
}

func TestRegistryApplyFilterExclude(t *testing.T) {
	r := registry(t)
	before := r.Len()
	r.ApplyFilter(nil, []string{"auth-bypass"})
	require.Equal(t, before-1, r.Len())
	require.Nil(t, r.Get("auth-bypass"))
}

func TestSnippetWindowBuiltCorrectly(t *testing.T) {
	r := registry(t)
	m := r.Get("command-injection")
	body := "// line 1\n// line 2\nsubprocess.run(['x'], shell=True)\n// line 4\n// line 5\n// line 6\n// line 7\n"
	hits := m.Match(body, "test.py")
	require.Len(t, hits, 1)
	require.Equal(t, []int{3}, hits[0].LineNumbers)
	require.Contains(t, hits[0].Snippet, "// line 2")
	require.Contains(t, hits[0].Snippet, "subprocess.run")
	require.Contains(t, hits[0].Snippet, "// line 4")
}
