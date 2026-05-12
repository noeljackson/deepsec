package processor

import (
	"fmt"

	"github.com/noeljackson/deepsec/internal/processor/providers"
)

// NewBackend constructs the appropriate AgentBackend for a profile.
// Both backend types are constructed here so the cli package doesn't
// have to know about the implementations. settings.Temperature /
// .TopP / .Seed are applied if non-nil; Seed is silently ignored on
// the Anthropic backend.
func NewBackend(profile *providers.Profile, model, apiKey string, settings ModelSettings) (AgentBackend, error) {
	if model == "" {
		model = profile.DefaultModel
	}
	switch profile.Kind {
	case providers.KindAnthropic:
		return NewAnthropicBackend(profile, model, apiKey).WithSettings(settings), nil
	case providers.KindOpenAIish:
		return NewOpenAICompatibleBackend(profile, model, apiKey).WithSettings(settings), nil
	}
	return nil, fmt.Errorf("unknown provider kind: %s", profile.Kind)
}
