// Package providers loads provider profiles (built-in TOML + user
// config) and resolves them to backend instances.
package providers

import (
	_ "embed"
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
	"github.com/noeljackson/deepsec/internal/core"
)

//go:embed profiles.toml
var bundledProfiles []byte

// Kind enumerates the backend implementations we ship. Each user-facing
// provider name maps to exactly one kind.
type Kind string

const (
	KindAnthropic Kind = "anthropic"
	KindOpenAIish Kind = "openai-compatible"
)

// PromptCache describes how a provider supports prompt caching.
type PromptCache string

const (
	CacheNone            PromptCache = "none"
	CacheAuto            PromptCache = "auto"
	CacheExplicit        PromptCache = "explicit"
	CacheMoonshotContext PromptCache = "moonshot-context"
)

// StructuredOutput describes the highest-fidelity response shape the
// provider supports. The OpenAI-compatible backend downgrades from
// json_schema → json_object → json_in_text as needed.
type StructuredOutput string

const (
	OutputJSONSchema StructuredOutput = "json_schema"
	OutputJSONObject StructuredOutput = "json_object"
	OutputJSONInText StructuredOutput = "json_in_text"
)

// Caps is the parsed `[providers.<name>.caps]` block.
type Caps struct {
	ToolUse          bool
	PromptCache      PromptCache
	StructuredOutput StructuredOutput
}

// PricingEntry is one row of a provider's pricing table. Cost is
// $/Mtok (one million tokens), to match the way providers publish it.
type PricingEntry struct {
	Model                string
	InputPerMTokUSD      float64
	OutputPerMTokUSD     float64
	CacheReadPerMTokUSD  float64
	CacheWritePerMTokUSD float64
}

// Profile is a resolved provider entry — ready to construct a backend.
type Profile struct {
	Name         string
	Kind         Kind
	BaseURL      string
	APIKeyEnv    string
	DefaultModel string
	Headers      map[string]string
	Caps         Caps
	Pricing      []PricingEntry
}

// Cost returns the USD cost for the given usage and model. Returns 0
// when the model isn't in the pricing table (don't extrapolate).
func (p *Profile) Cost(model string, u core.Usage) float64 {
	var price *PricingEntry
	for i := range p.Pricing {
		if p.Pricing[i].Model == model {
			price = &p.Pricing[i]
			break
		}
	}
	if price == nil {
		return 0
	}
	per := func(tokens uint64, rate float64) float64 {
		return float64(tokens) / 1_000_000.0 * rate
	}
	return per(u.InputTokens, price.InputPerMTokUSD) +
		per(u.OutputTokens, price.OutputPerMTokUSD) +
		per(u.CacheReadInputTokens, price.CacheReadPerMTokUSD) +
		per(u.CacheCreationInputTokens, price.CacheWritePerMTokUSD)
}

// Registry holds every known provider profile.
type Registry struct {
	profiles map[string]*Profile
}

func NewRegistry() *Registry {
	return &Registry{profiles: map[string]*Profile{}}
}

// LoadBuiltin loads the embedded profiles.toml pack.
func LoadBuiltin() (*Registry, error) {
	r := NewRegistry()
	if err := r.MergeTOMLBytes(bundledProfiles); err != nil {
		return nil, fmt.Errorf("built-in profiles: %w", err)
	}
	return r, nil
}

// MergeUserConfig folds `[providers.<name>]` blocks from a user's
// deepsec.config.toml into the registry. User entries replace built-ins
// at the same name.
func (r *Registry) MergeUserConfig(raw map[string]core.RawProvider) error {
	for name, rp := range raw {
		p, err := buildProfile(name, rp)
		if err != nil {
			return err
		}
		r.profiles[name] = p
	}
	return nil
}

// MergeTOMLBytes parses a TOML document that contains [providers.<name>]
// blocks at the top level. Used to load both the embedded profiles and
// any external TOML file via `--providers-file`.
func (r *Registry) MergeTOMLBytes(body []byte) error {
	var doc struct {
		Providers map[string]core.RawProvider `toml:"providers"`
	}
	if err := toml.Unmarshal(body, &doc); err != nil {
		return err
	}
	return r.MergeUserConfig(doc.Providers)
}

// Get returns the named profile, or nil.
func (r *Registry) Get(name string) *Profile { return r.profiles[name] }

// Names returns provider names in sorted order.
func (r *Registry) Names() []string {
	out := make([]string, 0, len(r.profiles))
	for k := range r.profiles {
		out = append(out, k)
	}
	return out
}

// All returns every profile in name order.
func (r *Registry) All() []*Profile {
	out := make([]*Profile, 0, len(r.profiles))
	for _, k := range r.Names() {
		out = append(out, r.profiles[k])
	}
	return out
}

// LookupKey returns the API key for `name`, reading the env var named
// in the profile.
func (r *Registry) LookupKey(name string) (string, error) {
	p := r.Get(name)
	if p == nil {
		return "", fmt.Errorf("unknown provider: %s", name)
	}
	v := os.Getenv(p.APIKeyEnv)
	if v == "" {
		return "", fmt.Errorf("missing %s env var (required by provider %q)", p.APIKeyEnv, name)
	}
	return v, nil
}

func buildProfile(name string, rp core.RawProvider) (*Profile, error) {
	kind := Kind(rp.Kind)
	if kind != KindAnthropic && kind != KindOpenAIish {
		return nil, fmt.Errorf("provider %q: unknown kind %q", name, rp.Kind)
	}
	caps, err := parseCaps(name, rp.Caps)
	if err != nil {
		return nil, err
	}
	prices := make([]PricingEntry, 0, len(rp.Pricing))
	for _, p := range rp.Pricing {
		prices = append(prices, PricingEntry{
			Model:                p.Model,
			InputPerMTokUSD:      p.InputPerMTokUSD,
			OutputPerMTokUSD:     p.OutputPerMTokUSD,
			CacheReadPerMTokUSD:  p.CacheReadPerMTokUSD,
			CacheWritePerMTokUSD: p.CacheWritePerMTokUSD,
		})
	}
	return &Profile{
		Name:         name,
		Kind:         kind,
		BaseURL:      rp.BaseURL,
		APIKeyEnv:    rp.APIKeyEnv,
		DefaultModel: rp.DefaultModel,
		Headers:      rp.Headers,
		Caps:         caps,
		Pricing:      prices,
	}, nil
}

func parseCaps(name string, raw map[string]any) (Caps, error) {
	c := Caps{
		ToolUse:          false,
		PromptCache:      CacheNone,
		StructuredOutput: OutputJSONInText,
	}
	for k, v := range raw {
		switch k {
		case "tool_use":
			b, ok := v.(bool)
			if !ok {
				return c, fmt.Errorf("provider %q caps.tool_use: want bool, got %T", name, v)
			}
			c.ToolUse = b
		case "prompt_cache":
			s, ok := v.(string)
			if !ok {
				return c, fmt.Errorf("provider %q caps.prompt_cache: want string, got %T", name, v)
			}
			c.PromptCache = PromptCache(s)
		case "structured_output":
			s, ok := v.(string)
			if !ok {
				return c, fmt.Errorf("provider %q caps.structured_output: want string, got %T", name, v)
			}
			c.StructuredOutput = StructuredOutput(s)
		}
	}
	return c, nil
}
