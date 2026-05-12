package processor

import (
	"fmt"

	"github.com/noeljackson/deepsec/internal/processor/providers"
)

// NewBackend constructs the appropriate AgentBackend for a profile.
// Both backend types are constructed here so the cli package doesn't
// have to know about the implementations.
func NewBackend(profile *providers.Profile, model, apiKey string) (AgentBackend, error) {
	if model == "" {
		model = profile.DefaultModel
	}
	switch profile.Kind {
	case providers.KindAnthropic:
		return NewAnthropicBackend(profile, model, apiKey), nil
	case providers.KindOpenAIish:
		return NewOpenAICompatibleBackend(profile, model, apiKey), nil
	}
	return nil, fmt.Errorf("unknown provider kind: %s", profile.Kind)
}
