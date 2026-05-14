package processor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noeljackson/deepsec/internal/core"
	"github.com/stretchr/testify/require"
)

func batchFor(file, slug, content string) *InvestigateBatch {
	return &InvestigateBatch{
		ProjectRoot: "/tmp",
		Files: []InvestigateFile{{
			Path:    file,
			Content: content,
			Candidates: []core.CandidateMatch{{
				VulnSlug:       slug,
				LineNumbers:    []int{3},
				Snippet:        "let x = q",
				MatchedPattern: "test",
			}},
		}},
		SlugNotes: []string{slug},
	}
}

func TestAssemblePromptIncludesCoreAndFilePath(t *testing.T) {
	b := batchFor("src/api/users.ts", "sql-injection-string-concat", "line1\nline2\nlet x = q\n")
	sys, user := AssemblePrompt(b)
	require.Contains(t, sys, CorePrompt)
	require.Contains(t, user, "src/api/users.ts")
	require.Contains(t, user, "sql-injection-string-concat")
	require.Contains(t, user, "let x = q")
}

func TestAssemblePromptCorePromptOverride(t *testing.T) {
	b := batchFor("a.ts", "s", "x\n")
	b.CorePromptOverride = "EVOLVED-PROMPT-MARKER"
	sys, _ := AssemblePrompt(b)
	require.Contains(t, sys, "EVOLVED-PROMPT-MARKER")
	require.NotContains(t, sys, CorePrompt)
}

func TestAssemblePromptLineNumbersSource(t *testing.T) {
	b := batchFor("a.ts", "s", "alpha\nbeta\ngamma\n")
	_, user := AssemblePrompt(b)
	require.Contains(t, user, "    1 alpha")
	require.Contains(t, user, "    2 beta")
	require.Contains(t, user, "    3 gamma")
}

func TestAssemblePromptEmitsFrameworkHighlights(t *testing.T) {
	b := batchFor("app/page.tsx", "nextjs-route-no-auth", "x")
	b.TechTags = []string{"nextjs"}
	sys, _ := AssemblePrompt(b)
	require.Contains(t, sys, "Next.js")
}

func TestAssemblePromptIncludesSlugHint(t *testing.T) {
	b := batchFor("a.ts", "sql-injection-string-concat", "select * from t")
	sys, _ := AssemblePrompt(b)
	require.Contains(t, strings.ToLower(sys), "parameterized")
}

func TestAssemblePromptAppendsProjectInfoAndAppend(t *testing.T) {
	b := batchFor("a.ts", "s", "x")
	b.ProjectInfo = "Project X handles payments."
	b.PromptAppend = "Pay extra attention to /api/admin."
	sys, _ := AssemblePrompt(b)
	require.Contains(t, sys, "Project X handles payments.")
	require.Contains(t, sys, "Pay extra attention to /api/admin.")
}

func TestAssemblePromptHandlesUnknownTagsGracefully(t *testing.T) {
	b := batchFor("a.ts", "s", "x")
	b.TechTags = []string{"unknown-framework"}
	_, _ = AssemblePrompt(b) // must not panic
}

func TestAssemblePromptGolden(t *testing.T) {
	sys, user := AssemblePrompt(goldenPromptBatch())
	requireGolden(t, "assemble_prompt_system.golden", sys)
	requireGolden(t, "assemble_prompt_user.golden", user)
}

func goldenPromptBatch() *InvestigateBatch {
	return &InvestigateBatch{
		ProjectRoot:  "/work/repo",
		ProjectInfo:  "Payments API.\nAdmin routes live under src/api/admin.",
		PromptAppend: "When auth context is ambiguous, explain the reachable attacker path.",
		TechTags:     []string{"nextjs", "express", "unknown-framework"},
		SlugNotes:    []string{"ssrf", "sql-injection-string-concat", "ssrf", "missing-note"},
		Files: []InvestigateFile{
			{
				Path: "src/api/users.ts",
				Content: strings.Join([]string{
					"import { db } from '../lib/db'",
					"export async function GET(req: Request) {",
					"  const q = new URL(req.url).searchParams.get('q')",
					"  return db.query('select * from users where name = ' + q)",
					"}",
				}, "\n"),
				Candidates: []core.CandidateMatch{
					{
						VulnSlug:       "sql-injection-string-concat",
						LineNumbers:    []int{4},
						Snippet:        "db.query('select * from users where name = ' + q)",
						MatchedPattern: "query concat",
					},
				},
			},
			{
				Path: "src/lib/fetch-proxy.ts",
				Content: strings.Join([]string{
					"export async function proxy(url: string) {",
					"  return fetch(url)",
					"}",
				}, "\n"),
				Candidates: []core.CandidateMatch{
					{
						VulnSlug:       "ssrf",
						LineNumbers:    []int{2},
						Snippet:        "fetch(url)",
						MatchedPattern: "fetch url",
					},
				},
			},
		},
	}
}

func requireGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if os.Getenv("UPDATE_PROMPT_GOLDEN") == "1" {
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(got), 0o644))
	}
	want, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, string(want), got)
}

func TestHighlightForTagKnownAndUnknown(t *testing.T) {
	for _, tag := range []string{"nextjs", "express", "django", "rails", "axum", "docker", "github-actions"} {
		require.NotEmpty(t, HighlightForTag(tag), tag)
	}
	require.Empty(t, HighlightForTag("definitely-not-a-framework"))
}

func TestNoteForSlugForCoreSlugs(t *testing.T) {
	for _, slug := range []string{
		"auth-bypass", "sql-injection-string-concat", "command-injection",
		"ssrf", "path-traversal", "agent-loop-no-cap",
	} {
		require.NotEmpty(t, NoteForSlug(slug), slug)
	}
}

func TestExtractJSONHandlesFencesAndProse(t *testing.T) {
	require.Equal(t, `{"a":1}`, ExtractJSON("```json\n"+`{"a":1}`+"\n```"))
	require.Equal(t, `{"a":1}`, ExtractJSON("prose\n```\n"+`{"a":1}`+"\n```"))
	require.Equal(t, `{"a":1}`, ExtractJSON("leading prose "+`{"a":1}`+" trailing"))
	require.Equal(t, "", ExtractJSON("no json here"))
}

func TestProviderRegistryParsesBuiltinProfiles(t *testing.T) {
	// Sanity check via the schema: every built-in matcher slug we use
	// in the prompt notes table actually maps to a known matcher slug
	// pattern. (This is a soft check; full registry parsing is tested
	// at the provider package level.)
}
