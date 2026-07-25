package prompts

import (
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/require"
)

func TestLoadEmbeddedProfile(t *testing.T) {
	p, err := Load(promptFiles)
	require.NoError(t, err)
	require.Equal(t, CorePrompt(), p.CorePrompt)
	require.NotEmpty(t, p.FrameworkHints)
	require.NotEmpty(t, p.CandidateNotes)
}

func TestLoadRejectsMissingFiles(t *testing.T) {
	_, err := Load(fstest.MapFS{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "core.md")
}

func TestLoadRejectsMalformedFiles(t *testing.T) {
	cases := map[string]fstest.MapFS{
		"malformed framework hints": validFS(map[string]string{
			frameworkHintsFile: "[[highlight]]\ntag = \n",
		}),
		"unknown framework key": validFS(map[string]string{
			frameworkHintsFile: "[[highlight]]\ntag = \"nextjs\"\ntext = \"x\"\nextra = \"no\"\n",
		}),
		"duplicate framework tag": validFS(map[string]string{
			frameworkHintsFile: "[[highlight]]\ntag = \"nextjs\"\ntext = \"x\"\n[[highlight]]\ntag = \"nextjs\"\ntext = \"y\"\n",
		}),
		"malformed slug hints": validFS(map[string]string{
			slugHintsFile: "[[note]]\nslug = \n",
		}),
		"unknown slug key": validFS(map[string]string{
			slugHintsFile: "[[note]]\nslug = \"ssrf\"\ntext = \"x\"\nextra = \"no\"\n",
		}),
		"empty slug text": validFS(map[string]string{
			slugHintsFile: "[[note]]\nslug = \"ssrf\"\ntext = \"   \"\n",
		}),
	}

	for name, fsys := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Load(fsys)
			require.Error(t, err)
		})
	}
}

func TestFrameworkHintCoverage(t *testing.T) {
	require.ElementsMatch(t, []string{
		"actix",
		"axum",
		"django",
		"docker",
		"express",
		"fastapi",
		"fastify",
		"flask",
		"github-actions",
		"helm",
		"gin",
		"nestjs",
		"nextjs",
		"rails",
	}, FrameworkTags())
}

func TestSlugNoteCoverage(t *testing.T) {
	require.ElementsMatch(t, []string{
		"agent-loop-no-cap",
		"agentic-untrusted-prompt-input",
		"auth-bypass",
		"axum-handler",
		"command-injection",
		"cors-wildcard",
		"dangerous-html",
		"dockerfile-mutable-tag",
		"github-workflow-pwn-request",
		"helm-workload-security-boundary",
		"k8s-privileged-pod",
		"mcp-tool-handler",
		"open-redirect",
		"path-traversal",
		"secret-plaintext",
		"rust-jwks-refresh-boundary",
		"rust-jwt-validation-boundary",
		"rust-process-command-from-input",
		"rust-proxy-credential-injection",
		"rust-secret-response-boundary",
		"rust-shell-command-execution",
		"sql-injection-string-concat",
		"ssrf",
		"svelte-basic-auth-boundary",
		"svelte-oidc-token-exchange-boundary",
		"weak-default-secret",
	}, Slugs())
}

func validFS(overrides map[string]string) fstest.MapFS {
	files := map[string]string{
		corePromptFile:     "core\n",
		frameworkHintsFile: "[[highlight]]\ntag = \"nextjs\"\ntext = \"x\"\n",
		slugHintsFile:      "[[note]]\nslug = \"ssrf\"\ntext = \"x\"\n",
	}
	for name, body := range overrides {
		files[name] = body
	}

	out := fstest.MapFS{}
	for name, body := range files {
		out[name] = &fstest.MapFile{Data: []byte(body)}
	}
	return out
}
