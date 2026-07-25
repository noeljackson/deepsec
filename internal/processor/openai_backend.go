package processor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/noeljackson/deepsec/internal/core"
	"github.com/noeljackson/deepsec/internal/processor/providers"
	agenttools "github.com/noeljackson/deepsec/internal/processor/tools"
	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/openai/openai-go/v3/shared"
)

// OpenAICompatibleBackend talks to anything that speaks the OpenAI
// Chat Completions API — OpenAI itself, Azure, OpenRouter, GLM, Kimi,
// DeepSeek, vLLM, Together, Groq, llama.cpp, … The capability flags on
// the profile drive which output mode + tool-use shape we use.
type OpenAICompatibleBackend struct {
	profile  *providers.Profile
	client   openai.Client
	model    string
	settings ModelSettings
}

func NewOpenAICompatibleBackend(profile *providers.Profile, model, apiKey string) *OpenAICompatibleBackend {
	opts := []option.RequestOption{option.WithAPIKey(apiKey)}
	if profile.BaseURL != "" {
		opts = append(opts, option.WithBaseURL(profile.BaseURL))
	}
	for k, v := range profile.Headers {
		opts = append(opts, option.WithHeader(k, v))
	}
	return &OpenAICompatibleBackend{
		profile: profile,
		client:  openai.NewClient(opts...),
		model:   model,
	}
}

// WithSettings returns the backend with sampling parameters pinned.
// Nil fields fall back to provider defaults.
func (b *OpenAICompatibleBackend) WithSettings(s ModelSettings) *OpenAICompatibleBackend {
	b.settings = s
	return b
}

// applySettings populates Temperature/TopP/Seed on chat-completion
// params when the caller pinned them.
func (b *OpenAICompatibleBackend) applySettings(p *openai.ChatCompletionNewParams) {
	if b.settings.Temperature != nil {
		p.Temperature = openai.Float(*b.settings.Temperature)
	}
	if b.settings.TopP != nil {
		p.TopP = openai.Float(*b.settings.TopP)
	}
	if b.settings.Seed != nil {
		p.Seed = openai.Int(*b.settings.Seed)
	}
}

func (b *OpenAICompatibleBackend) Kind() providers.Kind { return providers.KindOpenAIish }
func (b *OpenAICompatibleBackend) Model() string        { return b.model }

func (b *OpenAICompatibleBackend) ProposePatchJSON(ctx context.Context, system, user string, schema json.RawMessage) (string, core.Usage, float64, error) {
	start := time.Now()
	params := openai.ChatCompletionNewParams{
		Model: b.model,
		Messages: []openai.ChatCompletionMessageParamUnion{
			openai.SystemMessage(system),
			openai.UserMessage(user),
		},
	}
	b.applySchemaFor(&params, "propose_matcher_patch", "Return one bounded matcher TOML patch decision.", schema)
	b.applySettings(&params)
	resp, err := b.client.Chat.Completions.New(ctx, params)
	if err != nil {
		if isOpenAIQuotaErr(err) {
			return "", core.Usage{}, 0, &QuotaExhaustedError{Provider: b.profile.Name, Detail: err.Error()}
		}
		return "", core.Usage{}, 0, fmt.Errorf("%s: %w", b.profile.Name, err)
	}
	_ = start
	usage := openaiUsage(resp)
	body := extractJSONFromChatResp(resp)
	if body == "" {
		return "", usage, b.profile.Cost(b.model, usage), errors.New("patch proposer returned no JSON")
	}
	return body, usage, b.profile.Cost(b.model, usage), nil
}

func (b *OpenAICompatibleBackend) Investigate(ctx context.Context, batch *InvestigateBatch) (*InvestigateOutput, error) {
	if batch.ToolsEnabled {
		if !b.profile.Caps.ToolUse {
			return nil, fmt.Errorf("%s: --tools requires provider tool_use capability", b.profile.Name)
		}
		return runAgenticInvestigation(ctx, batch, b, toolLoopOptions{
			MaxTurns:   batch.MaxTurns,
			MaxCostUSD: batch.MaxCostUSD,
		})
	}

	system, user := AssemblePrompt(batch)
	start := time.Now()

	params := openai.ChatCompletionNewParams{
		Model: b.model,
		Messages: []openai.ChatCompletionMessageParamUnion{
			openai.SystemMessage(system),
			openai.UserMessage(user),
		},
	}
	b.applyStructuredOutputForInvestigate(&params)
	b.applySettings(&params)

	resp, err := b.client.Chat.Completions.New(ctx, params)
	if err != nil {
		if isOpenAIQuotaErr(err) {
			return nil, &QuotaExhaustedError{Provider: b.profile.Name, Detail: err.Error()}
		}
		return nil, fmt.Errorf("%s: %w", b.profile.Name, err)
	}
	dur := uint64(time.Since(start).Milliseconds())

	usage := openaiUsage(resp)
	jsonBody, err := b.extractJSONInvestigate(resp)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", b.profile.Name, err)
	}
	if jsonBody == "" {
		return emptyOutput(batch, usage, dur), nil
	}
	var env FindingsEnvelope
	if err := json.Unmarshal([]byte(jsonBody), &env); err != nil {
		return emptyOutput(batch, usage, dur), nil
	}
	if env.Refusal != "" {
		return &InvestigateOutput{
			Refusal:    &core.RefusalReport{Refused: true, Reason: env.Refusal},
			Usage:      usage,
			DurationMs: dur,
		}, nil
	}
	out, err := buildInvestigateOutput(batch, env, usage, dur)
	if err != nil {
		return nil, fmt.Errorf("%s: invalid finding envelope: %w", b.profile.Name, err)
	}
	out.CostUSD = b.profile.Cost(b.model, usage)
	return out, nil
}

func (b *OpenAICompatibleBackend) SendToolLoop(ctx context.Context, system, user string, turns []toolLoopTurn, localTools []agenttools.Tool) (toolLoopResponse, error) {
	messages := []openai.ChatCompletionMessageParamUnion{
		openai.SystemMessage(system),
		openai.UserMessage(user),
	}
	for _, turn := range turns {
		asst := openai.ChatCompletionAssistantMessageParam{}
		for _, call := range turn.Calls {
			asst.ToolCalls = append(asst.ToolCalls, openai.ChatCompletionMessageToolCallUnionParam{
				OfFunction: &openai.ChatCompletionMessageFunctionToolCallParam{
					ID: call.ID,
					Function: openai.ChatCompletionMessageFunctionToolCallFunctionParam{
						Name:      call.Name,
						Arguments: string(call.Args),
					},
				},
			})
		}
		messages = append(messages, openai.ChatCompletionMessageParamUnion{OfAssistant: &asst})
		for _, result := range turn.Results {
			messages = append(messages, openai.ToolMessage(result.Content, result.Call.ID))
		}
	}

	params := openai.ChatCompletionNewParams{
		Model:    b.model,
		Messages: messages,
		ToolChoice: openai.ChatCompletionToolChoiceOptionUnionParam{
			OfAuto: openai.String(string(openai.ChatCompletionToolChoiceOptionAutoAuto)),
		},
		ParallelToolCalls: openai.Bool(false),
	}
	params.Tools = append(params.Tools, openaiTool(reportFindingsToolName, "Report each genuine vulnerability found. Omit false positives.", FindingsSchema, b.profile.Caps.StructuredOutput == providers.OutputJSONSchema))
	for _, local := range localTools {
		params.Tools = append(params.Tools, openaiTool(local.Name(), "Read-only repository investigation tool.", local.Schema(), false))
	}
	b.applySettings(&params)
	resp, err := b.client.Chat.Completions.New(ctx, params)
	if err != nil {
		if isOpenAIQuotaErr(err) {
			return toolLoopResponse{}, &QuotaExhaustedError{Provider: b.profile.Name, Detail: err.Error()}
		}
		return toolLoopResponse{}, fmt.Errorf("%s: %w", b.profile.Name, err)
	}
	out := toolLoopResponse{Usage: openaiUsage(resp)}
	out.Cost = b.profile.Cost(b.model, out.Usage)
	if len(resp.Choices) == 0 {
		return out, nil
	}
	msg := resp.Choices[0].Message
	out.Text = msg.Content
	for _, tc := range msg.ToolCalls {
		if tc.Type != "function" {
			continue
		}
		args := json.RawMessage(tc.Function.Arguments)
		if tc.Function.Name == reportFindingsToolName {
			out.Report = args
			return out, nil
		}
		out.Calls = append(out.Calls, toolLoopCall{ID: tc.ID, Name: tc.Function.Name, Args: args})
	}
	return out, nil
}

func (b *OpenAICompatibleBackend) Revalidate(ctx context.Context, in *RevalidateInput) ([]RevalidatedFinding, core.Usage, uint64, error) {
	system, user := BuildRevalidatePrompt(in)
	start := time.Now()
	params := openai.ChatCompletionNewParams{
		Model: b.model,
		Messages: []openai.ChatCompletionMessageParamUnion{
			openai.SystemMessage(system),
			openai.UserMessage(user),
		},
	}
	b.applyStructuredOutputForRevalidate(&params)
	b.applySettings(&params)

	resp, err := b.client.Chat.Completions.New(ctx, params)
	if err != nil {
		if isOpenAIQuotaErr(err) {
			return nil, core.Usage{}, 0, &QuotaExhaustedError{Provider: b.profile.Name, Detail: err.Error()}
		}
		return nil, core.Usage{}, 0, err
	}
	dur := uint64(time.Since(start).Milliseconds())
	usage := openaiUsage(resp)
	jsonBody, err := b.extractJSONRevalidate(resp)
	if err != nil || jsonBody == "" {
		return nil, usage, dur, nil
	}
	var env RevalidateEnvelope
	if err := json.Unmarshal([]byte(jsonBody), &env); err != nil {
		return nil, usage, dur, nil
	}
	return env.Revalidations, usage, dur, nil
}

func (b *OpenAICompatibleBackend) Triage(ctx context.Context, in *TriageInput) (*TriagedFinding, core.Usage, uint64, error) {
	system, user := BuildTriagePrompt(in)
	start := time.Now()
	params := openai.ChatCompletionNewParams{
		Model: b.model,
		Messages: []openai.ChatCompletionMessageParamUnion{
			openai.SystemMessage(system),
			openai.UserMessage(user),
		},
	}
	b.applyStructuredOutputForTriage(&params)
	b.applySettings(&params)
	resp, err := b.client.Chat.Completions.New(ctx, params)
	if err != nil {
		if isOpenAIQuotaErr(err) {
			return nil, core.Usage{}, 0, &QuotaExhaustedError{Provider: b.profile.Name, Detail: err.Error()}
		}
		return nil, core.Usage{}, 0, err
	}
	dur := uint64(time.Since(start).Milliseconds())
	usage := openaiUsage(resp)
	jsonBody, err := b.extractJSONTriage(resp)
	if err != nil {
		return nil, usage, dur, err
	}
	if jsonBody == "" {
		return nil, usage, dur, errors.New("triage: no response payload")
	}
	var t TriagedFinding
	if err := json.Unmarshal([]byte(jsonBody), &t); err != nil {
		return nil, usage, dur, fmt.Errorf("triage: %w", err)
	}
	return &t, usage, dur, nil
}

// --- structured-output adaptation ---

func (b *OpenAICompatibleBackend) applyStructuredOutputForInvestigate(p *openai.ChatCompletionNewParams) {
	b.applySchemaFor(p, "report_findings", "Report each genuine vulnerability found.", FindingsSchema)
}

func (b *OpenAICompatibleBackend) applyStructuredOutputForRevalidate(p *openai.ChatCompletionNewParams) {
	b.applySchemaFor(p, "revalidate_findings", "Return the verdict for each input finding.", RevalidateSchema)
}

func (b *OpenAICompatibleBackend) applyStructuredOutputForTriage(p *openai.ChatCompletionNewParams) {
	b.applySchemaFor(p, "triage_finding", "Triage the input finding.", TriageSchema)
}

// applySchemaFor picks the highest-fidelity output mode the provider
// supports and configures the request accordingly. The cascade is:
//
//	tool_use=true  → register the schema as a tool; force the call
//	otherwise json_schema → response_format: json_schema (strict)
//	otherwise json_object → response_format: json_object (loose)
//	otherwise            → leave it as plain text; the caller falls back to ExtractJSON
func (b *OpenAICompatibleBackend) applySchemaFor(p *openai.ChatCompletionNewParams, toolName, desc string, schema json.RawMessage) {
	if b.profile.Caps.ToolUse {
		p.Tools = []openai.ChatCompletionToolUnionParam{openaiTool(toolName, desc, schema, b.profile.Caps.StructuredOutput == providers.OutputJSONSchema)}
		p.ToolChoice = openai.ToolChoiceOptionFunctionToolChoice(
			openai.ChatCompletionNamedToolChoiceFunctionParam{Name: toolName},
		)
		return
	}
	switch b.profile.Caps.StructuredOutput {
	case providers.OutputJSONSchema:
		var schemaMap map[string]any
		_ = json.Unmarshal(schema, &schemaMap)
		p.ResponseFormat = openai.ChatCompletionNewParamsResponseFormatUnion{
			OfJSONSchema: &shared.ResponseFormatJSONSchemaParam{
				JSONSchema: shared.ResponseFormatJSONSchemaJSONSchemaParam{
					Name:   toolName,
					Schema: schemaMap,
					Strict: openai.Bool(true),
				},
			},
		}
	case providers.OutputJSONObject:
		p.ResponseFormat = openai.ChatCompletionNewParamsResponseFormatUnion{
			OfJSONObject: &shared.ResponseFormatJSONObjectParam{},
		}
	}
}

func openaiTool(name, desc string, schema json.RawMessage, strict bool) openai.ChatCompletionToolUnionParam {
	var schemaMap map[string]any
	_ = json.Unmarshal(schema, &schemaMap)
	return openai.ChatCompletionFunctionTool(shared.FunctionDefinitionParam{
		Name:        name,
		Description: openai.String(desc),
		Parameters:  schemaMap,
		Strict:      openai.Bool(strict),
	})
}

// extractJSONInvestigate pulls the JSON envelope out of the response,
// preferring tool-call arguments over message content.
func (b *OpenAICompatibleBackend) extractJSONInvestigate(resp *openai.ChatCompletion) (string, error) {
	return extractJSONFromChatResp(resp), nil
}
func (b *OpenAICompatibleBackend) extractJSONRevalidate(resp *openai.ChatCompletion) (string, error) {
	return extractJSONFromChatResp(resp), nil
}
func (b *OpenAICompatibleBackend) extractJSONTriage(resp *openai.ChatCompletion) (string, error) {
	return extractJSONFromChatResp(resp), nil
}

func extractJSONFromChatResp(resp *openai.ChatCompletion) string {
	if len(resp.Choices) == 0 {
		return ""
	}
	msg := resp.Choices[0].Message
	for _, tc := range msg.ToolCalls {
		args := tc.Function.Arguments
		if args != "" {
			return args
		}
	}
	if msg.Content != "" {
		// JSON-mode responses are clean JSON; JSON-in-text responses
		// may have prose around them. Try both.
		trimmed := strings.TrimSpace(msg.Content)
		if strings.HasPrefix(trimmed, "{") {
			return trimmed
		}
		if extracted := ExtractJSON(msg.Content); extracted != "" {
			return extracted
		}
	}
	return ""
}

func openaiUsage(resp *openai.ChatCompletion) core.Usage {
	return core.Usage{
		InputTokens:          uint64(resp.Usage.PromptTokens),
		OutputTokens:         uint64(resp.Usage.CompletionTokens),
		CacheReadInputTokens: uint64(resp.Usage.PromptTokensDetails.CachedTokens),
	}
}

func isOpenAIQuotaErr(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "429"),
		strings.Contains(strings.ToLower(s), "rate limit"),
		strings.Contains(strings.ToLower(s), "quota"),
		strings.Contains(s, "insufficient_quota"):
		return true
	}
	return false
}
