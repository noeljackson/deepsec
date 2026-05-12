package processor

// ModelSettings captures the inference knobs that need to be pinned
// per run for reproducibility. Unset fields (nil pointers) mean
// "use whatever the provider's SDK default is" — no behavior change.
//
// Seed is honored on OpenAI-compatible providers (the SDK exposes it);
// Anthropic does not expose seed on the Messages API, so it is silently
// ignored there.
type ModelSettings struct {
	Temperature *float64
	TopP        *float64
	Seed        *int64
}

// AsMap returns a JSON-shaped snapshot of the settings actually being
// applied, for persistence in `core.ProcessorConfig.ModelConfig` and
// per-call `core.AnalysisEntry.ModelConfig`. Fields that are unset
// (nil) are omitted so the saved record honestly reflects what was
// pinned vs. what was left to the SDK default.
func (s ModelSettings) AsMap() map[string]any {
	out := map[string]any{}
	if s.Temperature != nil {
		out["temperature"] = *s.Temperature
	}
	if s.TopP != nil {
		out["top_p"] = *s.TopP
	}
	if s.Seed != nil {
		out["seed"] = *s.Seed
	}
	return out
}
