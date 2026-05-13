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

func TestProposePatchAcceptsASTPattern(t *testing.T) {
	patch, err := ProposePatch(context.Background(), patchJSONMockBackend{
		body: `{"decision":"ast_pattern","ast_language":"python","ast_query":"(call function: (identifier) @fn (#eq? @fn \"eval\")) @match","ast_prefilter":"eval\\(","rationale":"narrow eval to direct calls"}`,
	}, "python-eval-exec", nil, nil, `[[matcher]]`)
	require.NoError(t, err)
	require.Equal(t, "ast_pattern", patch.Decision)
	require.Equal(t, "python", patch.AstLanguage)
	require.Contains(t, patch.AstQuery, "@match")
	require.Equal(t, "eval\\(", patch.AstPrefilter)
}

func TestProposePatchASTRequiresLanguageAndQuery(t *testing.T) {
	_, err := ProposePatch(context.Background(), patchJSONMockBackend{
		body: `{"decision":"ast_pattern","ast_query":"(identifier) @x"}`,
	}, "x", nil, nil, `[[matcher]]`)
	require.Error(t, err)
	require.Contains(t, err.Error(), "ast_language")

	_, err = ProposePatch(context.Background(), patchJSONMockBackend{
		body: `{"decision":"ast_pattern","ast_language":"go"}`,
	}, "x", nil, nil, `[[matcher]]`)
	require.Error(t, err)
	require.Contains(t, err.Error(), "ast_query")
}

func TestProposePatchRejectsMixedFields(t *testing.T) {
	// suppress_pattern + ast_query in the same patch is the kind of
	// model confusion the schema must catch.
	_, err := ProposePatch(context.Background(), patchJSONMockBackend{
		body: `{"decision":"suppress_pattern","suppress_pattern":"(?i)x","ast_query":"(identifier) @match"}`,
	}, "x", nil, nil, `[[matcher]]`)
	require.Error(t, err)
}

func TestPatchSummaryAST(t *testing.T) {
	p := Patch{Decision: "ast_pattern", AstLanguage: "python", AstQuery: "(call) @match"}
	require.Contains(t, p.Summary(), "python")
	require.Contains(t, p.Summary(), "AST")
}
