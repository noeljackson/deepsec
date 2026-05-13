package processor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
	"github.com/noeljackson/deepsec/internal/core"
	"github.com/noeljackson/deepsec/internal/processor/providers"
	agenttools "github.com/noeljackson/deepsec/internal/processor/tools"
)

// AnthropicBackend talks to Anthropic's Messages API via the official
// SDK. Uses prompt caching on the system prompt and tool use for
// structured output.
type AnthropicBackend struct {
	profile  *providers.Profile
	client   anthropic.Client
	model    string
	apiKey   string
	settings ModelSettings
}

func NewAnthropicBackend(profile *providers.Profile, model, apiKey string) *AnthropicBackend {
	opts := []option.RequestOption{option.WithAPIKey(apiKey)}
	for k, v := range profile.Headers {
		opts = append(opts, option.WithHeader(k, v))
	}
	baseURL := profile.BaseURL
	if baseURL == "" {
		baseURL = os.Getenv("ANTHROPIC_BASE_URL")
	}
	if baseURL != "" {
		opts = append(opts, option.WithBaseURL(baseURL))
	}
	return &AnthropicBackend{
		profile: profile,
		client:  anthropic.NewClient(opts...),
		model:   model,
		apiKey:  apiKey,
	}
}

// WithSettings returns the backend with sampling parameters pinned.
// Nil fields fall back to provider defaults. Seed is silently ignored
// — the Anthropic Messages API does not expose seed.
func (b *AnthropicBackend) WithSettings(s ModelSettings) *AnthropicBackend {
	b.settings = s
	return b
}

// applySettings populates Temperature/TopP on message-create params
// when the caller pinned them.
func (b *AnthropicBackend) applySettings(p *anthropic.MessageNewParams) {
	if b.settings.Temperature != nil {
		p.Temperature = anthropic.Float(*b.settings.Temperature)
	}
	if b.settings.TopP != nil {
		p.TopP = anthropic.Float(*b.settings.TopP)
	}
}

func (b *AnthropicBackend) Kind() providers.Kind { return providers.KindAnthropic }
func (b *AnthropicBackend) Model() string        { return b.model }

func (b *AnthropicBackend) ProposePatchJSON(ctx context.Context, system, user string, schema json.RawMessage) (string, core.Usage, float64, error) {
	toolName := "propose_matcher_patch"
	tool := anthropic.ToolParam{
		Name:        toolName,
		Description: anthropic.String("Return one bounded matcher TOML patch decision."),
		InputSchema: anthropic.ToolInputSchemaParam{
			Type:       "object",
			Properties: schemaPropertiesFor(schema),
			Required:   []string{"decision"},
		},
	}
	start := time.Now()
	params := anthropic.MessageNewParams{
		Model:     anthropic.Model(b.model),
		MaxTokens: 2048,
		System: []anthropic.TextBlockParam{{
			Text:         system,
			CacheControl: anthropic.CacheControlEphemeralParam{Type: "ephemeral"},
		}},
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(user)),
		},
		Tools: []anthropic.ToolUnionParam{{OfTool: &tool}},
		ToolChoice: anthropic.ToolChoiceUnionParam{
			OfTool: &anthropic.ToolChoiceToolParam{Name: toolName},
		},
	}
	b.applySettings(&params)
	resp, err := b.client.Messages.New(ctx, params)
	if err != nil {
		if isAnthropicQuotaErr(err) {
			return "", core.Usage{}, 0, &QuotaExhaustedError{Provider: b.profile.Name, Detail: err.Error()}
		}
		return "", core.Usage{}, 0, fmt.Errorf("anthropic: %w", err)
	}
	usage := core.Usage{
		InputTokens:              uint64(resp.Usage.InputTokens),
		OutputTokens:             uint64(resp.Usage.OutputTokens),
		CacheReadInputTokens:     uint64(resp.Usage.CacheReadInputTokens),
		CacheCreationInputTokens: uint64(resp.Usage.CacheCreationInputTokens),
	}
	_ = start
	for _, block := range resp.Content {
		if tu := block.AsToolUse(); tu.Name == toolName {
			return string(tu.Input), usage, b.profile.Cost(b.model, usage), nil
		}
	}
	text := concatTextBlocks(resp.Content)
	if body := ExtractJSON(text); body != "" {
		return body, usage, b.profile.Cost(b.model, usage), nil
	}
	return "", usage, b.profile.Cost(b.model, usage), errors.New("anthropic: patch response missing tool call")
}

// Investigate sends one batch to Claude with prompt caching on the
// system prompt and a `report_findings` tool the model invokes to
// return structured output.
func (b *AnthropicBackend) Investigate(ctx context.Context, batch *InvestigateBatch) (*InvestigateOutput, error) {
	if batch.ToolsEnabled {
		return runAgenticInvestigation(ctx, batch, b, toolLoopOptions{
			MaxTurns:   batch.MaxTurns,
			MaxCostUSD: batch.MaxCostUSD,
		})
	}

	system, user := AssemblePrompt(batch)

	systemBlocks := []anthropic.TextBlockParam{
		{
			Text: system,
			// Cache the system prompt; it's stable across a run, so
			// subsequent batches hit the cache for ~10% of the input cost.
			CacheControl: anthropic.CacheControlEphemeralParam{Type: "ephemeral"},
		},
	}

	toolName := "report_findings"
	tool := anthropic.ToolParam{
		Name:        toolName,
		Description: anthropic.String("Report each genuine vulnerability found. Omit false positives."),
		InputSchema: anthropic.ToolInputSchemaParam{
			Type:       "object",
			Properties: schemaPropertiesFor(FindingsSchema),
			Required:   []string{"findings"},
		},
	}

	start := time.Now()
	params := anthropic.MessageNewParams{
		Model:     anthropic.Model(b.model),
		MaxTokens: 8192,
		System:    systemBlocks,
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(user)),
		},
		Tools: []anthropic.ToolUnionParam{{OfTool: &tool}},
		ToolChoice: anthropic.ToolChoiceUnionParam{
			OfTool: &anthropic.ToolChoiceToolParam{Name: toolName},
		},
	}
	b.applySettings(&params)
	resp, err := b.client.Messages.New(ctx, params)
	if err != nil {
		if isAnthropicQuotaErr(err) {
			return nil, &QuotaExhaustedError{Provider: b.profile.Name, Detail: err.Error()}
		}
		return nil, fmt.Errorf("anthropic: %w", err)
	}
	durationMs := uint64(time.Since(start).Milliseconds())

	usage := core.Usage{
		InputTokens:              uint64(resp.Usage.InputTokens),
		OutputTokens:             uint64(resp.Usage.OutputTokens),
		CacheReadInputTokens:     uint64(resp.Usage.CacheReadInputTokens),
		CacheCreationInputTokens: uint64(resp.Usage.CacheCreationInputTokens),
	}

	// Pull the tool-use block out of the response and parse its input.
	for _, block := range resp.Content {
		if tu := block.AsToolUse(); tu.Name == toolName {
			var env FindingsEnvelope
			if err := json.Unmarshal(tu.Input, &env); err != nil {
				return nil, fmt.Errorf("anthropic: parsing tool input: %w", err)
			}
			if env.Refusal != "" {
				return &InvestigateOutput{
					Refusal:    &core.RefusalReport{Refused: true, Reason: env.Refusal},
					Usage:      usage,
					DurationMs: durationMs,
				}, nil
			}
			out := buildInvestigateOutput(batch, env, usage, durationMs)
			out.CostUSD = b.profile.Cost(b.model, usage)
			return out, nil
		}
	}

	// Tool call missing — fall back to parsing text as JSON.
	text := concatTextBlocks(resp.Content)
	if json := ExtractJSON(text); json != "" {
		var env FindingsEnvelope
		if err := decodeStrict(json, &env); err == nil {
			if env.Refusal != "" {
				return &InvestigateOutput{
					Refusal:    &core.RefusalReport{Refused: true, Reason: env.Refusal},
					Usage:      usage,
					DurationMs: durationMs,
				}, nil
			}
			out := buildInvestigateOutput(batch, env, usage, durationMs)
			out.CostUSD = b.profile.Cost(b.model, usage)
			return out, nil
		}
	}
	return emptyOutput(batch, usage, durationMs), nil
}

func (b *AnthropicBackend) SendToolLoop(ctx context.Context, system, user string, turns []toolLoopTurn, localTools []agenttools.Tool) (toolLoopResponse, error) {
	systemBlocks := []anthropic.TextBlockParam{{
		Text:         system,
		CacheControl: anthropic.CacheControlEphemeralParam{Type: "ephemeral"},
	}}
	tools := []anthropic.ToolUnionParam{{OfTool: &anthropic.ToolParam{
		Name:        reportFindingsToolName,
		Description: anthropic.String("Report each genuine vulnerability found. Omit false positives."),
		InputSchema: anthropic.ToolInputSchemaParam{
			Type:       "object",
			Properties: schemaPropertiesFor(FindingsSchema),
			Required:   []string{"findings"},
		},
	}}}
	for _, local := range localTools {
		tool := anthropic.ToolParam{
			Name:        local.Name(),
			Description: anthropic.String("Read-only repository investigation tool."),
			InputSchema: anthropic.ToolInputSchemaParam{
				Type:       "object",
				Properties: schemaPropertiesFor(local.Schema()),
				Required:   schemaRequiredFor(local.Schema()),
			},
		}
		tools = append(tools, anthropic.ToolUnionParam{OfTool: &tool})
	}

	messages := []anthropic.MessageParam{anthropic.NewUserMessage(anthropic.NewTextBlock(user))}
	for _, turn := range turns {
		assistantBlocks := make([]anthropic.ContentBlockParamUnion, 0, len(turn.Calls))
		for _, call := range turn.Calls {
			assistantBlocks = append(assistantBlocks, anthropic.NewToolUseBlock(call.ID, rawJSONAsAny(call.Args), call.Name))
		}
		messages = append(messages, anthropic.NewAssistantMessage(assistantBlocks...))
		resultBlocks := make([]anthropic.ContentBlockParamUnion, 0, len(turn.Results))
		for _, result := range turn.Results {
			resultBlocks = append(resultBlocks, anthropic.NewToolResultBlock(result.Call.ID, result.Content, result.IsError))
		}
		messages = append(messages, anthropic.NewUserMessage(resultBlocks...))
	}

	params := anthropic.MessageNewParams{
		Model:     anthropic.Model(b.model),
		MaxTokens: 8192,
		System:    systemBlocks,
		Messages:  messages,
		Tools:     tools,
		ToolChoice: anthropic.ToolChoiceUnionParam{
			OfAuto: &anthropic.ToolChoiceAutoParam{DisableParallelToolUse: anthropic.Bool(true)},
		},
	}
	b.applySettings(&params)
	resp, err := b.client.Messages.New(ctx, params)
	if err != nil {
		if isAnthropicQuotaErr(err) {
			return toolLoopResponse{}, &QuotaExhaustedError{Provider: b.profile.Name, Detail: err.Error()}
		}
		return toolLoopResponse{}, fmt.Errorf("anthropic: %w", err)
	}
	out := toolLoopResponse{
		Usage: core.Usage{
			InputTokens:              uint64(resp.Usage.InputTokens),
			OutputTokens:             uint64(resp.Usage.OutputTokens),
			CacheReadInputTokens:     uint64(resp.Usage.CacheReadInputTokens),
			CacheCreationInputTokens: uint64(resp.Usage.CacheCreationInputTokens),
		},
	}
	out.Cost = b.profile.Cost(b.model, out.Usage)
	for _, block := range resp.Content {
		if tu := block.AsToolUse(); tu.Name != "" {
			raw := json.RawMessage(tu.Input)
			if tu.Name == reportFindingsToolName {
				out.Report = raw
				return out, nil
			}
			out.Calls = append(out.Calls, toolLoopCall{ID: tu.ID, Name: tu.Name, Args: raw})
			continue
		}
		if tb := block.AsText(); tb.Text != "" {
			out.Text += tb.Text
		}
	}
	return out, nil
}

func (b *AnthropicBackend) Revalidate(ctx context.Context, in *RevalidateInput) ([]RevalidatedFinding, core.Usage, uint64, error) {
	system, user := BuildRevalidatePrompt(in)
	toolName := "revalidate_findings"
	tool := anthropic.ToolParam{
		Name:        toolName,
		Description: anthropic.String("Return the verdict for each input finding."),
		InputSchema: anthropic.ToolInputSchemaParam{
			Type:       "object",
			Properties: schemaPropertiesFor(RevalidateSchema),
			Required:   []string{"revalidations"},
		},
	}

	start := time.Now()
	revalParams := anthropic.MessageNewParams{
		Model:     anthropic.Model(b.model),
		MaxTokens: 4096,
		System: []anthropic.TextBlockParam{{Text: system,
			CacheControl: anthropic.CacheControlEphemeralParam{Type: "ephemeral"},
		}},
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(user)),
		},
		Tools: []anthropic.ToolUnionParam{{OfTool: &tool}},
		ToolChoice: anthropic.ToolChoiceUnionParam{
			OfTool: &anthropic.ToolChoiceToolParam{Name: toolName},
		},
	}
	b.applySettings(&revalParams)
	resp, err := b.client.Messages.New(ctx, revalParams)
	if err != nil {
		if isAnthropicQuotaErr(err) {
			return nil, core.Usage{}, 0, &QuotaExhaustedError{Provider: b.profile.Name, Detail: err.Error()}
		}
		return nil, core.Usage{}, 0, err
	}
	dur := uint64(time.Since(start).Milliseconds())
	usage := core.Usage{
		InputTokens:              uint64(resp.Usage.InputTokens),
		OutputTokens:             uint64(resp.Usage.OutputTokens),
		CacheReadInputTokens:     uint64(resp.Usage.CacheReadInputTokens),
		CacheCreationInputTokens: uint64(resp.Usage.CacheCreationInputTokens),
	}
	for _, block := range resp.Content {
		if tu := block.AsToolUse(); tu.Name == toolName {
			var env RevalidateEnvelope
			if err := json.Unmarshal(tu.Input, &env); err == nil {
				return env.Revalidations, usage, dur, nil
			}
		}
	}
	return nil, usage, dur, nil
}

func (b *AnthropicBackend) Triage(ctx context.Context, in *TriageInput) (*TriagedFinding, core.Usage, uint64, error) {
	system, user := BuildTriagePrompt(in)
	toolName := "triage_finding"
	tool := anthropic.ToolParam{
		Name:        toolName,
		Description: anthropic.String("Triage the input finding."),
		InputSchema: anthropic.ToolInputSchemaParam{
			Type:       "object",
			Properties: schemaPropertiesFor(TriageSchema),
			Required:   []string{"priority", "exploitability", "impact", "reasoning"},
		},
	}
	start := time.Now()
	triageParams := anthropic.MessageNewParams{
		Model:     anthropic.Model(b.model),
		MaxTokens: 1024,
		System:    []anthropic.TextBlockParam{{Text: system}},
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(user)),
		},
		Tools: []anthropic.ToolUnionParam{{OfTool: &tool}},
		ToolChoice: anthropic.ToolChoiceUnionParam{
			OfTool: &anthropic.ToolChoiceToolParam{Name: toolName},
		},
	}
	b.applySettings(&triageParams)
	resp, err := b.client.Messages.New(ctx, triageParams)
	if err != nil {
		if isAnthropicQuotaErr(err) {
			return nil, core.Usage{}, 0, &QuotaExhaustedError{Provider: b.profile.Name, Detail: err.Error()}
		}
		return nil, core.Usage{}, 0, err
	}
	dur := uint64(time.Since(start).Milliseconds())
	usage := core.Usage{
		InputTokens:              uint64(resp.Usage.InputTokens),
		OutputTokens:             uint64(resp.Usage.OutputTokens),
		CacheReadInputTokens:     uint64(resp.Usage.CacheReadInputTokens),
		CacheCreationInputTokens: uint64(resp.Usage.CacheCreationInputTokens),
	}
	for _, block := range resp.Content {
		if tu := block.AsToolUse(); tu.Name == toolName {
			var t TriagedFinding
			if err := json.Unmarshal(tu.Input, &t); err == nil {
				return &t, usage, dur, nil
			}
		}
	}
	return nil, usage, dur, errors.New("anthropic: triage response missing tool call")
}

// --- helpers ---

func concatTextBlocks(blocks []anthropic.ContentBlockUnion) string {
	var b strings.Builder
	for _, blk := range blocks {
		if tb := blk.AsText(); tb.Text != "" {
			b.WriteString(tb.Text)
		}
	}
	return b.String()
}

// schemaPropertiesFor extracts the "properties" sub-object from a JSON
// Schema document so we can pass it via the Anthropic SDK's
// ToolInputSchemaParam, which wants individual property maps rather
// than a full schema.
func schemaPropertiesFor(raw json.RawMessage) map[string]any {
	var schema struct {
		Properties map[string]any `json:"properties"`
	}
	_ = json.Unmarshal(raw, &schema)
	return schema.Properties
}

func schemaRequiredFor(raw json.RawMessage) []string {
	var schema struct {
		Required []string `json:"required"`
	}
	_ = json.Unmarshal(raw, &schema)
	return schema.Required
}

func rawJSONAsAny(raw json.RawMessage) any {
	var out any
	if err := json.Unmarshal(raw, &out); err != nil {
		return map[string]any{}
	}
	return out
}

func isAnthropicQuotaErr(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	if strings.Contains(s, "rate_limit") || strings.Contains(s, "Rate limit") {
		return true
	}
	if strings.Contains(s, "quota") || strings.Contains(s, "429") {
		return true
	}
	return false
}

func decodeStrict(s string, v any) error {
	d := json.NewDecoder(strings.NewReader(s))
	d.DisallowUnknownFields()
	return d.Decode(v)
}

func buildInvestigateOutput(batch *InvestigateBatch, env FindingsEnvelope, usage core.Usage, durationMs uint64) *InvestigateOutput {
	byFile := map[string][]ProducedFinding{}
	for _, ef := range env.Findings {
		f := ProducedFinding{
			Severity:       core.Severity(ef.Severity),
			VulnSlug:       ef.VulnSlug,
			Title:          ef.Title,
			Description:    ef.Description,
			LineNumbers:    ef.LineNumbers,
			Recommendation: ef.Recommendation,
			Confidence:     core.Confidence(ef.Confidence),
		}
		byFile[ef.FilePath] = append(byFile[ef.FilePath], f)
	}
	results := make([]InvestigateResult, 0, len(batch.Files))
	for _, f := range batch.Files {
		results = append(results, InvestigateResult{
			FilePath: f.Path,
			Findings: byFile[f.Path],
		})
	}
	return &InvestigateOutput{
		Results:    results,
		Usage:      usage,
		DurationMs: durationMs,
		NumTurns:   1,
	}
}

func emptyOutput(batch *InvestigateBatch, usage core.Usage, durationMs uint64) *InvestigateOutput {
	results := make([]InvestigateResult, 0, len(batch.Files))
	for _, f := range batch.Files {
		results = append(results, InvestigateResult{FilePath: f.Path})
	}
	return &InvestigateOutput{Results: results, Usage: usage, DurationMs: durationMs, NumTurns: 1}
}
