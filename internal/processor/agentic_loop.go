package processor

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/noeljackson/deepsec/internal/core"
	agenttools "github.com/noeljackson/deepsec/internal/processor/tools"
)

const (
	reportFindingsToolName = "report_findings"
	maxToolCallsPerTurn    = 8
)

type toolLoopCall struct {
	ID   string
	Name string
	Args json.RawMessage
}

type toolLoopResult struct {
	Call    toolLoopCall
	Content string
	IsError bool
}

type toolLoopTurn struct {
	Calls   []toolLoopCall
	Results []toolLoopResult
}

type toolLoopResponse struct {
	Calls  []toolLoopCall
	Report json.RawMessage
	Text   string
	Usage  core.Usage
	Cost   float64
}

type toolLoopClient interface {
	SendToolLoop(ctx context.Context, system, user string, turns []toolLoopTurn, tools []agenttools.Tool) (toolLoopResponse, error)
}

type toolLoopOptions struct {
	MaxTurns   int
	MaxCostUSD float64
}

func runAgenticInvestigation(ctx context.Context, batch *InvestigateBatch, client toolLoopClient, opts toolLoopOptions) (*InvestigateOutput, error) {
	system, user := AssemblePrompt(batch)
	system += "\n\nAgentic investigation tools are available. Use read-only tools when candidate context is insufficient. When finished, call report_findings exactly once; omit false positives."

	maxTurns := opts.MaxTurns
	if maxTurns < 1 {
		maxTurns = 8
	}

	localTools := agenttools.New(batch.ProjectRoot)
	localByName := agenttools.ByName(localTools)
	turns := []toolLoopTurn{}
	totalUsage := core.Usage{}
	totalCost := 0.0
	start := time.Now()

	for turn := 1; turn <= maxTurns; turn++ {
		resp, err := client.SendToolLoop(ctx, system, user, turns, localTools)
		if err != nil {
			return nil, err
		}
		totalUsage = addUsage(totalUsage, resp.Usage)
		totalCost += resp.Cost
		durationMs := uint64(time.Since(start).Milliseconds())

		if len(resp.Report) > 0 {
			var env FindingsEnvelope
			if err := json.Unmarshal(resp.Report, &env); err != nil {
				return nil, fmt.Errorf("agentic report_findings: %w", err)
			}
			if env.Refusal != "" {
				return &InvestigateOutput{
					Refusal:    &core.RefusalReport{Refused: true, Reason: core.RedactSecrets(env.Refusal)},
					Usage:      totalUsage,
					DurationMs: durationMs,
					NumTurns:   turn,
					CostUSD:    totalCost,
				}, nil
			}
			out, err := buildInvestigateOutput(batch, env, totalUsage, durationMs)
			if err != nil {
				return nil, fmt.Errorf("agentic report_findings: %w", err)
			}
			out.NumTurns = turn
			out.CostUSD = totalCost
			return out, nil
		}

		if opts.MaxCostUSD > 0 && totalCost >= opts.MaxCostUSD {
			return refusalOutput(totalUsage, durationMs, turn, totalCost, "cost cap reached during agentic investigation"), nil
		}

		if len(resp.Calls) == 0 {
			reason := "model returned no tool call"
			if resp.Text != "" {
				reason = "model returned text without report_findings"
			}
			return refusalOutput(totalUsage, durationMs, turn, totalCost, reason), nil
		}
		if len(resp.Calls) > maxToolCallsPerTurn {
			return refusalOutput(totalUsage, durationMs, turn, totalCost, "tool call cap reached during agentic investigation"), nil
		}

		results := make([]toolLoopResult, 0, len(resp.Calls))
		for _, call := range resp.Calls {
			if call.Name == reportFindingsToolName {
				var env FindingsEnvelope
				if err := json.Unmarshal(call.Args, &env); err != nil {
					return nil, fmt.Errorf("agentic report_findings: %w", err)
				}
				if env.Refusal != "" {
					return &InvestigateOutput{
						Refusal:    &core.RefusalReport{Refused: true, Reason: core.RedactSecrets(env.Refusal)},
						Usage:      totalUsage,
						DurationMs: durationMs,
						NumTurns:   turn,
						CostUSD:    totalCost,
					}, nil
				}
				out, err := buildInvestigateOutput(batch, env, totalUsage, durationMs)
				if err != nil {
					return nil, fmt.Errorf("agentic report_findings: %w", err)
				}
				out.NumTurns = turn
				out.CostUSD = totalCost
				return out, nil
			}
			tool := localByName[call.Name]
			if tool == nil {
				results = append(results, toolLoopResult{
					Call:    call,
					Content: fmt.Sprintf("unknown tool %q", call.Name),
					IsError: true,
				})
				continue
			}
			content, err := tool.Run(ctx, call.Args)
			if err != nil {
				results = append(results, toolLoopResult{Call: call, Content: core.RedactSecrets(err.Error()), IsError: true})
				continue
			}
			results = append(results, toolLoopResult{Call: call, Content: content})
		}
		safeCalls := make([]toolLoopCall, len(resp.Calls))
		for i, call := range resp.Calls {
			safeCalls[i] = call
			safeArgs := core.RedactSecrets(string(call.Args))
			if json.Valid([]byte(safeArgs)) {
				safeCalls[i].Args = json.RawMessage(safeArgs)
			} else {
				safeCalls[i].Args = json.RawMessage("{}")
			}
		}
		for i := range results {
			results[i].Call = safeCalls[i]
		}
		turns = append(turns, toolLoopTurn{Calls: safeCalls, Results: results})
	}

	return refusalOutput(totalUsage, uint64(time.Since(start).Milliseconds()), maxTurns, totalCost, "max tool turns reached"), nil
}

func refusalOutput(usage core.Usage, durationMs uint64, turns int, cost float64, reason string) *InvestigateOutput {
	return &InvestigateOutput{
		Refusal:    &core.RefusalReport{Refused: true, Reason: reason},
		Usage:      usage,
		DurationMs: durationMs,
		NumTurns:   turns,
		CostUSD:    cost,
	}
}

func addUsage(a, b core.Usage) core.Usage {
	return core.Usage{
		InputTokens:              a.InputTokens + b.InputTokens,
		OutputTokens:             a.OutputTokens + b.OutputTokens,
		CacheReadInputTokens:     a.CacheReadInputTokens + b.CacheReadInputTokens,
		CacheCreationInputTokens: a.CacheCreationInputTokens + b.CacheCreationInputTokens,
	}
}
