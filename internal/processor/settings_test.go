package processor

import (
	"context"
	"testing"

	"github.com/noeljackson/deepsec/internal/core"
	"github.com/stretchr/testify/require"
)

func TestModelSettingsAsMapOmitsUnsetFields(t *testing.T) {
	s := ModelSettings{}
	require.Empty(t, s.AsMap())

	temp := 0.0
	s.Temperature = &temp
	m := s.AsMap()
	require.Len(t, m, 1)
	require.Equal(t, 0.0, m["temperature"])
	require.NotContains(t, m, "top_p")
	require.NotContains(t, m, "seed")
}

func TestModelSettingsAsMapIncludesAllSetFields(t *testing.T) {
	temp := 0.2
	topP := 0.9
	seed := int64(42)
	s := ModelSettings{Temperature: &temp, TopP: &topP, Seed: &seed}
	m := s.AsMap()
	require.Equal(t, 0.2, m["temperature"])
	require.Equal(t, 0.9, m["top_p"])
	require.Equal(t, int64(42), m["seed"])
}

func TestProcessPersistsModelSettingsInRunMeta(t *testing.T) {
	e := newEnv(t)
	e.seedRecord(t, "src/a.ts", core.StatusPending, "mock-slug")

	temp := 0.1
	seed := int64(7)
	opts := baseOpts(e, NewMockBackend())
	opts.ModelSettings = ModelSettings{Temperature: &temp, Seed: &seed}

	out, err := Process(context.Background(), opts)
	require.NoError(t, err)
	require.Equal(t, 1, out.AnalysisCount)

	meta, err := e.dataRoot.ReadRunMeta(e.projectID, out.RunID)
	require.NoError(t, err)
	require.NotNil(t, meta.ProcessorConfig)
	// JSON round-trip widens all numbers to float64 in map[string]any.
	require.Equal(t, 0.1, meta.ProcessorConfig.ModelConfig["temperature"])
	require.Equal(t, float64(7), meta.ProcessorConfig.ModelConfig["seed"])
	require.NotContains(t, meta.ProcessorConfig.ModelConfig, "top_p")

	rec := e.readBack(t, "src/a.ts")
	require.Len(t, rec.AnalysisHistory, 1)
	require.Equal(t, 0.1, rec.AnalysisHistory[0].ModelConfig["temperature"])
	require.Equal(t, float64(7), rec.AnalysisHistory[0].ModelConfig["seed"])
}

func TestProcessOmitsModelConfigWhenSettingsUnset(t *testing.T) {
	e := newEnv(t)
	e.seedRecord(t, "src/a.ts", core.StatusPending, "mock-slug")

	out, err := Process(context.Background(), baseOpts(e, NewMockBackend()))
	require.NoError(t, err)

	meta, err := e.dataRoot.ReadRunMeta(e.projectID, out.RunID)
	require.NoError(t, err)
	require.NotNil(t, meta.ProcessorConfig)
	require.Empty(t, meta.ProcessorConfig.ModelConfig, "ModelConfig should be empty when no settings pinned")
}
