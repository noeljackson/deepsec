package core

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

// DeepsecConfig is the top-level shape of `deepsec.config.toml`.
type DeepsecConfig struct {
	Projects     []ProjectDeclaration   `toml:"projects"`
	DataDir      string                 `toml:"data_dir,omitempty"`
	DefaultAgent string                 `toml:"default_agent,omitempty"`
	Matchers     MatcherFilter          `toml:"matchers"`
	Providers    map[string]RawProvider `toml:"providers,omitempty"`
}

// MatcherFilter is the `[matchers]` block.
type MatcherFilter struct {
	Only       []string `toml:"only"`
	Exclude    []string `toml:"exclude"`
	ExtraPaths []string `toml:"extra_paths"`
}

// ProjectDeclaration is one `[[projects]]` entry.
type ProjectDeclaration struct {
	ID            string   `toml:"id"`
	Root          string   `toml:"root"`
	GithubURL     string   `toml:"github_url,omitempty"`
	InfoMarkdown  string   `toml:"info_markdown,omitempty"`
	PromptAppend  string   `toml:"prompt_append,omitempty"`
	PriorityPaths []string `toml:"priority_paths,omitempty"`
}

// RawProvider is the on-disk shape of a `[providers.<name>]` entry.
// The processor package's own `Profile` type wraps this plus parsed
// capability flags; keeping the on-disk shape here keeps deepsec-core
// free of processor dependencies.
type RawProvider struct {
	Kind         string            `toml:"kind"`
	BaseURL      string            `toml:"base_url,omitempty"`
	APIKeyEnv    string            `toml:"api_key_env"`
	DefaultModel string            `toml:"default_model"`
	Headers      map[string]string `toml:"headers,omitempty"`
	Caps         map[string]any    `toml:"caps,omitempty"`
	Pricing      []RawPricingEntry `toml:"pricing,omitempty"`
}

// RawPricingEntry is one `[[providers.<name>.pricing]]` row.
type RawPricingEntry struct {
	Model                string  `toml:"model"`
	InputPerMTokUSD      float64 `toml:"input_per_mtok_usd"`
	OutputPerMTokUSD     float64 `toml:"output_per_mtok_usd"`
	CacheReadPerMTokUSD  float64 `toml:"cache_read_per_mtok_usd,omitempty"`
	CacheWritePerMTokUSD float64 `toml:"cache_write_per_mtok_usd,omitempty"`
}

// FindProject returns the named project or nil.
func (c *DeepsecConfig) FindProject(id string) *ProjectDeclaration {
	if c == nil {
		return nil
	}
	for i := range c.Projects {
		if c.Projects[i].ID == id {
			return &c.Projects[i]
		}
	}
	return nil
}

var configFiles = []string{
	"deepsec.config.toml",
	".deepsec/config.toml",
	"deepsec.toml",
}

// FindConfigFile walks up from `start` looking for a known config name.
// Returns the absolute path, or "" if none found.
func FindConfigFile(start string) string {
	cur, err := filepath.Abs(start)
	if err != nil {
		return ""
	}
	for {
		for _, name := range configFiles {
			p := filepath.Join(cur, name)
			if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
				return p
			}
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return ""
		}
		cur = parent
	}
}

var ErrNoProjects = errors.New("config has no projects[]")

// LoadConfig parses the TOML at `path` and validates it has at least
// one project. Returns ErrNoProjects when the projects[] array is
// empty so callers can produce a friendly error.
func LoadConfig(path string) (*DeepsecConfig, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var cfg DeepsecConfig
	if err := toml.Unmarshal(body, &cfg); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if len(cfg.Projects) == 0 {
		return nil, ErrNoProjects
	}
	return &cfg, nil
}
