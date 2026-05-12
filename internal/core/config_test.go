package core

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParsesMinimalConfig(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "deepsec.config.toml")
	require.NoError(t, os.WriteFile(p, []byte(`default_agent = "openai"
[[projects]]
id = "p"
root = "."
`), 0o644))
	cfg, err := LoadConfig(p)
	require.NoError(t, err)
	require.Equal(t, "openai", cfg.DefaultAgent)
	require.Len(t, cfg.Projects, 1)
	require.Equal(t, ".", cfg.FindProject("p").Root)
	require.Nil(t, cfg.FindProject("nope"))
}

func TestParsesFullConfig(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "deepsec.config.toml")
	require.NoError(t, os.WriteFile(p, []byte(`
default_agent = "anthropic"
data_dir = "my-data"

[matchers]
only = ["a", "b"]
exclude = ["c"]
extra_paths = ["./x.toml"]

[[projects]]
id = "first"
root = "./apps/first"
github_url = "https://github.com/o/r/blob/main"
info_markdown = "ctx"
prompt_append = "be careful"
priority_paths = ["src/", "lib/"]

[[projects]]
id = "second"
root = "/abs/path"

[providers.custom]
kind = "openai-compatible"
base_url = "https://custom.example.com/v1"
api_key_env = "CUSTOM_KEY"
default_model = "custom-model"
caps = { tool_use = true, prompt_cache = "none", structured_output = "json_object" }
`), 0o644))
	cfg, err := LoadConfig(p)
	require.NoError(t, err)
	require.Equal(t, "my-data", cfg.DataDir)
	require.Equal(t, []string{"a", "b"}, cfg.Matchers.Only)
	require.Len(t, cfg.Projects, 2)
	first := cfg.FindProject("first")
	require.NotNil(t, first)
	require.Equal(t, "https://github.com/o/r/blob/main", first.GithubURL)
	require.Contains(t, cfg.Providers, "custom")
	require.Equal(t, "openai-compatible", cfg.Providers["custom"].Kind)
}

func TestNoProjectsReturnsError(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "deepsec.config.toml")
	require.NoError(t, os.WriteFile(p, []byte(`default_agent = "anthropic"`), 0o644))
	_, err := LoadConfig(p)
	require.True(t, errors.Is(err, ErrNoProjects))
}

func TestFindConfigFileWalksUpFromSubdir(t *testing.T) {
	d := t.TempDir()
	cfgPath := filepath.Join(d, "deepsec.config.toml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(`[[projects]]
id = "x"
root = "."
`), 0o644))
	nested := filepath.Join(d, "a", "b", "c")
	require.NoError(t, os.MkdirAll(nested, 0o755))
	found := FindConfigFile(nested)
	require.Equal(t, cfgPath, found)
}

func TestFindConfigFileNoneFound(t *testing.T) {
	d := t.TempDir()
	require.Equal(t, "", FindConfigFile(d))
}

func TestFindConfigFileDotDeepsecVariant(t *testing.T) {
	d := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(d, ".deepsec"), 0o755))
	cfgPath := filepath.Join(d, ".deepsec", "config.toml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(`[[projects]]
id = "x"
root = "."
`), 0o644))
	require.Equal(t, cfgPath, FindConfigFile(d))
}
