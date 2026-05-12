package providers

import (
	"testing"

	"github.com/noeljackson/deepsec/internal/core"
	"github.com/stretchr/testify/require"
)

func TestLoadBuiltinIncludesExpectedProviders(t *testing.T) {
	r, err := LoadBuiltin()
	require.NoError(t, err)
	for _, name := range []string{"anthropic", "openai", "glm", "kimi", "deepseek", "openrouter"} {
		require.NotNilf(t, r.Get(name), "missing built-in provider: %s", name)
	}
}

func TestAnthropicProfileShape(t *testing.T) {
	r, err := LoadBuiltin()
	require.NoError(t, err)
	p := r.Get("anthropic")
	require.NotNil(t, p)
	require.Equal(t, KindAnthropic, p.Kind)
	require.Equal(t, "ANTHROPIC_API_KEY", p.APIKeyEnv)
	require.Equal(t, "claude-sonnet-4-6", p.DefaultModel)
	require.True(t, p.Caps.ToolUse)
	require.Equal(t, CacheExplicit, p.Caps.PromptCache)
	require.NotEmpty(t, p.Pricing)
}

func TestOpenAIProfileShape(t *testing.T) {
	r, err := LoadBuiltin()
	require.NoError(t, err)
	p := r.Get("openai")
	require.NotNil(t, p)
	require.Equal(t, KindOpenAIish, p.Kind)
	require.Equal(t, "https://api.openai.com/v1", p.BaseURL)
	require.Equal(t, OutputJSONSchema, p.Caps.StructuredOutput)
}

func TestGLMProfileShape(t *testing.T) {
	r, err := LoadBuiltin()
	require.NoError(t, err)
	p := r.Get("glm")
	require.NotNil(t, p)
	require.Equal(t, KindOpenAIish, p.Kind)
	require.Equal(t, "ZAI_API_KEY", p.APIKeyEnv)
	require.Equal(t, CacheNone, p.Caps.PromptCache)
	require.Equal(t, OutputJSONObject, p.Caps.StructuredOutput)
}

func TestKimiProfileShape(t *testing.T) {
	r, err := LoadBuiltin()
	require.NoError(t, err)
	p := r.Get("kimi")
	require.NotNil(t, p)
	require.Equal(t, "MOONSHOT_API_KEY", p.APIKeyEnv)
	require.Equal(t, CacheMoonshotContext, p.Caps.PromptCache)
}

func TestCostForKnownModel(t *testing.T) {
	r, err := LoadBuiltin()
	require.NoError(t, err)
	p := r.Get("anthropic")
	require.NotNil(t, p)
	u := core.Usage{InputTokens: 1_000_000, OutputTokens: 1_000_000}
	cost := p.Cost("claude-sonnet-4-6", u)
	require.InDelta(t, 18.00, cost, 0.001) // 3.00 + 15.00
}

func TestCostForUnknownModelIsZero(t *testing.T) {
	r, err := LoadBuiltin()
	require.NoError(t, err)
	p := r.Get("anthropic")
	require.Equal(t, 0.0, p.Cost("not-a-model", core.Usage{InputTokens: 1_000_000}))
}

func TestMergeUserConfigOverridesBuiltin(t *testing.T) {
	r, err := LoadBuiltin()
	require.NoError(t, err)
	err = r.MergeUserConfig(map[string]core.RawProvider{
		"anthropic": {
			Kind:         "anthropic",
			APIKeyEnv:    "MY_KEY",
			DefaultModel: "claude-opus-4-7",
		},
	})
	require.NoError(t, err)
	p := r.Get("anthropic")
	require.Equal(t, "MY_KEY", p.APIKeyEnv)
	require.Equal(t, "claude-opus-4-7", p.DefaultModel)
}

func TestMergeUserConfigAddsNewProvider(t *testing.T) {
	r, err := LoadBuiltin()
	require.NoError(t, err)
	err = r.MergeUserConfig(map[string]core.RawProvider{
		"azure-deploy": {
			Kind:         "openai-compatible",
			BaseURL:      "https://example.openai.azure.com",
			APIKeyEnv:    "AZURE_KEY",
			DefaultModel: "gpt-4",
		},
	})
	require.NoError(t, err)
	p := r.Get("azure-deploy")
	require.NotNil(t, p)
	require.Equal(t, "AZURE_KEY", p.APIKeyEnv)
}

func TestMergeUserConfigRejectsUnknownKind(t *testing.T) {
	r, err := LoadBuiltin()
	require.NoError(t, err)
	err = r.MergeUserConfig(map[string]core.RawProvider{
		"bogus": {Kind: "made-up-thing", APIKeyEnv: "X", DefaultModel: "y"},
	})
	require.Error(t, err)
}

func TestLookupKeyMissingEnvFails(t *testing.T) {
	r, err := LoadBuiltin()
	require.NoError(t, err)
	t.Setenv("ANTHROPIC_API_KEY", "")
	_, err = r.LookupKey("anthropic")
	require.Error(t, err)
}

func TestLookupKeyWithEnvSucceeds(t *testing.T) {
	r, err := LoadBuiltin()
	require.NoError(t, err)
	t.Setenv("ANTHROPIC_API_KEY", "fake")
	key, err := r.LookupKey("anthropic")
	require.NoError(t, err)
	require.Equal(t, "fake", key)
}
