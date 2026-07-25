package processor

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/noeljackson/deepsec/internal/core"
	agenttools "github.com/noeljackson/deepsec/internal/processor/tools"
	"github.com/stretchr/testify/require"
)

type scriptedToolLoopClient struct {
	responses []toolLoopResponse
	turns     [][]toolLoopTurn
}

func (c *scriptedToolLoopClient) SendToolLoop(ctx context.Context, system, user string, turns []toolLoopTurn, tools []agenttools.Tool) (toolLoopResponse, error) {
	if err := ctx.Err(); err != nil {
		return toolLoopResponse{}, err
	}
	copied := append([]toolLoopTurn(nil), turns...)
	c.turns = append(c.turns, copied)
	if len(c.responses) == 0 {
		return toolLoopResponse{Text: "done"}, nil
	}
	resp := c.responses[0]
	c.responses = c.responses[1:]
	return resp, nil
}

func TestRunAgenticInvestigationDispatchesToolSequence(t *testing.T) {
	root := t.TempDir()
	writeAgenticSource(t, root, "src/app.ts", "const id = req.params.id;\ndb.query('select ' + id);\n")
	report := FindingsEnvelope{Findings: []EnvelopeFinding{{
		FilePath: "src/app.ts", Severity: string(core.SeverityHigh), VulnSlug: "sql-injection",
		Title: "SQL injection", Description: "id reaches query", LineNumbers: []int{2},
		Recommendation: "Use parameterized queries.", Confidence: string(core.ConfidenceHigh),
	}}}
	reportJSON, _ := json.Marshal(report)
	client := &scriptedToolLoopClient{responses: []toolLoopResponse{
		{Calls: []toolLoopCall{{ID: "call_1", Name: "grep", Args: mustRaw(map[string]any{"pattern": "db\\.query"})}}, Usage: core.Usage{InputTokens: 10}, Cost: 0.01},
		{Calls: []toolLoopCall{{ID: "call_2", Name: "read_file", Args: mustRaw(map[string]any{"path": "src/app.ts"})}}, Usage: core.Usage{OutputTokens: 5}, Cost: 0.02},
		{Report: reportJSON, Usage: core.Usage{OutputTokens: 20}, Cost: 0.03},
	}}

	out, err := runAgenticInvestigation(context.Background(), agenticBatch(root), client, toolLoopOptions{MaxTurns: 8})
	require.NoError(t, err)
	require.Nil(t, out.Refusal)
	require.Equal(t, 3, out.NumTurns)
	require.Equal(t, 0.06, out.CostUSD)
	require.Equal(t, uint64(10), out.Usage.InputTokens)
	require.Len(t, out.Results, 1)
	require.Len(t, out.Results[0].Findings, 1)

	require.Len(t, client.turns, 3)
	require.Empty(t, client.turns[0])
	require.Len(t, client.turns[1], 1)
	require.Equal(t, "grep", client.turns[1][0].Calls[0].Name)
	require.Contains(t, client.turns[1][0].Results[0].Content, "src/app.ts:2")
	require.Len(t, client.turns[2], 2)
	require.Equal(t, "read_file", client.turns[2][1].Calls[0].Name)
	require.Contains(t, client.turns[2][1].Results[0].Content, "db.query")
}

func TestRunAgenticInvestigationTurnCap(t *testing.T) {
	root := t.TempDir()
	writeAgenticSource(t, root, "src/app.ts", "const id = req.params.id;\n")
	client := &scriptedToolLoopClient{responses: []toolLoopResponse{
		{Calls: []toolLoopCall{{ID: "call_1", Name: "grep", Args: mustRaw(map[string]any{"pattern": "id"})}}},
		{Calls: []toolLoopCall{{ID: "call_2", Name: "grep", Args: mustRaw(map[string]any{"pattern": "id"})}}},
	}}
	out, err := runAgenticInvestigation(context.Background(), agenticBatch(root), client, toolLoopOptions{MaxTurns: 2})
	require.NoError(t, err)
	require.NotNil(t, out.Refusal)
	require.Contains(t, out.Refusal.Reason, "max tool turns")
	require.Equal(t, 2, out.NumTurns)
}

func TestRunAgenticInvestigationTextWithoutToolIsRefusal(t *testing.T) {
	root := t.TempDir()
	writeAgenticSource(t, root, "src/app.ts", "const id = req.params.id;\n")
	client := &scriptedToolLoopClient{responses: []toolLoopResponse{{Text: "I cannot tell"}}}
	out, err := runAgenticInvestigation(context.Background(), agenticBatch(root), client, toolLoopOptions{MaxTurns: 8})
	require.NoError(t, err)
	require.NotNil(t, out.Refusal)
	require.Contains(t, out.Refusal.Reason, "text without report_findings")
}

func TestRunAgenticInvestigationCostCap(t *testing.T) {
	root := t.TempDir()
	writeAgenticSource(t, root, "src/app.ts", "const id = req.params.id;\n")
	client := &scriptedToolLoopClient{responses: []toolLoopResponse{{
		Calls: []toolLoopCall{{ID: "call_1", Name: "grep", Args: mustRaw(map[string]any{"pattern": "id"})}},
		Cost:  0.50,
	}}}
	out, err := runAgenticInvestigation(context.Background(), agenticBatch(root), client, toolLoopOptions{MaxTurns: 8, MaxCostUSD: 0.25})
	require.NoError(t, err)
	require.NotNil(t, out.Refusal)
	require.Contains(t, out.Refusal.Reason, "cost cap")
}

func TestRunAgenticInvestigationPerTurnToolCallCap(t *testing.T) {
	root := t.TempDir()
	writeAgenticSource(t, root, "src/app.ts", "const id = req.params.id;\n")
	calls := make([]toolLoopCall, maxToolCallsPerTurn+1)
	for i := range calls {
		calls[i] = toolLoopCall{ID: "call", Name: "grep", Args: mustRaw(map[string]any{"pattern": "id"})}
	}
	client := &scriptedToolLoopClient{responses: []toolLoopResponse{{Calls: calls}}}
	out, err := runAgenticInvestigation(context.Background(), agenticBatch(root), client, toolLoopOptions{MaxTurns: 8, MaxCostUSD: 1})
	require.NoError(t, err)
	require.NotNil(t, out.Refusal)
	require.Contains(t, out.Refusal.Reason, "tool call cap")
	require.Len(t, client.turns, 1)
}

func TestRunAgenticInvestigationRedactsToolArgumentsBeforeNextProviderTurn(t *testing.T) {
	root := t.TempDir()
	writeAgenticSource(t, root, "src/app.ts", "const id = req.params.id;\n")
	secret := "sk-test-abcdefghijklmnopqrstuvwxyz"
	client := &scriptedToolLoopClient{responses: []toolLoopResponse{
		{Calls: []toolLoopCall{{ID: "call_1", Name: "grep", Args: mustRaw(map[string]any{"pattern": secret})}}},
		{Text: "done"},
	}}
	out, err := runAgenticInvestigation(context.Background(), agenticBatch(root), client, toolLoopOptions{MaxTurns: 8, MaxCostUSD: 1})
	require.NoError(t, err)
	require.NotNil(t, out.Refusal)
	require.Len(t, client.turns, 2)
	require.NotContains(t, string(client.turns[1][0].Calls[0].Args), secret)
	require.Contains(t, string(client.turns[1][0].Calls[0].Args), "[REDACTED]")
}

func TestRunAgenticInvestigationRejectsFindingWithoutValidEvidence(t *testing.T) {
	root := t.TempDir()
	writeAgenticSource(t, root, "src/app.ts", "const id = req.params.id;\n")
	report, err := json.Marshal(FindingsEnvelope{Findings: []EnvelopeFinding{{
		FilePath: "outside.ts", Severity: "HIGH", VulnSlug: "ssrf", Title: "bad", Description: "bad", LineNumbers: []int{1}, Recommendation: "fix", Confidence: "high",
	}}})
	require.NoError(t, err)
	client := &scriptedToolLoopClient{responses: []toolLoopResponse{{Report: report}}}
	_, err = runAgenticInvestigation(context.Background(), agenticBatch(root), client, toolLoopOptions{MaxTurns: 8, MaxCostUSD: 1})
	require.Error(t, err)
	require.Contains(t, err.Error(), "outside the batch")
}

func agenticBatch(root string) *InvestigateBatch {
	body, err := os.ReadFile(filepath.Join(root, "src", "app.ts"))
	if err != nil {
		panic(err)
	}
	return &InvestigateBatch{
		ProjectRoot: root,
		Files: []InvestigateFile{{
			Path:    "src/app.ts",
			Content: string(body),
			Candidates: []core.CandidateMatch{{
				VulnSlug: "sql-injection", LineNumbers: []int{2}, Snippet: "db.query", MatchedPattern: "db.query",
			}},
		}},
	}
}

func writeAgenticSource(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
	require.NoError(t, os.WriteFile(p, []byte(body), 0o644))
}

func mustRaw(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}
