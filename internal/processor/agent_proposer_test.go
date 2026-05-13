package processor

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/noeljackson/deepsec/internal/core"
	"github.com/noeljackson/deepsec/internal/processor/providers"
	"github.com/stretchr/testify/require"
)

type patchJSONMockBackend struct {
	body string
}

func (m patchJSONMockBackend) Kind() providers.Kind { return providers.KindAnthropic }
func (m patchJSONMockBackend) Model() string        { return "mock-patch" }
func (m patchJSONMockBackend) ProposePatchJSON(context.Context, string, string, json.RawMessage) (string, core.Usage, float64, error) {
	return m.body, core.Usage{}, 0, nil
}
func (m patchJSONMockBackend) Investigate(context.Context, *InvestigateBatch) (*InvestigateOutput, error) {
	return nil, nil
}
func (m patchJSONMockBackend) Revalidate(context.Context, *RevalidateInput) ([]RevalidatedFinding, core.Usage, uint64, error) {
	return nil, core.Usage{}, 0, nil
}
func (m patchJSONMockBackend) Triage(context.Context, *TriageInput) (*TriagedFinding, core.Usage, uint64, error) {
	return nil, core.Usage{}, 0, nil
}

func TestProposePatchParsesStrictSchema(t *testing.T) {
	patch, err := ProposePatch(context.Background(), patchJSONMockBackend{
		body: `{"decision":"suppress_pattern","suppress_pattern":"(?i)safe_route","rationale":"scope a known decoy"}`,
	}, "flask-route", nil, nil, `[[matcher]]`)
	require.NoError(t, err)
	require.Equal(t, "suppress_pattern", patch.Decision)
	require.Equal(t, "(?i)safe_route", patch.SuppressPattern)
	require.Equal(t, "scope a known decoy", patch.Rationale)
}

func TestParsePatchRejectsUnknownFields(t *testing.T) {
	_, err := ParsePatch(`{"decision":"require_content","require_content":"request","patterns":["bad"]}`)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown field")
}
