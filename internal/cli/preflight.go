package cli

import (
	"fmt"
	"os"
)

// Preflight returns an error if the provider's API key env var is unset.
// Used by `deepsec preflight` and called automatically before AI
// commands (process / revalidate / triage).
func Preflight(ctx *Context, agent string) error {
	p := ctx.Providers.Get(agent)
	if p == nil {
		return fmt.Errorf("unknown provider %q (run `deepsec list-providers`)", agent)
	}
	if p.APIKeyEnv != "" && os.Getenv(p.APIKeyEnv) == "" {
		return fmt.Errorf("missing %s env var (required by provider %q)", p.APIKeyEnv, agent)
	}
	return nil
}
