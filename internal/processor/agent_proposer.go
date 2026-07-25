package processor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/noeljackson/deepsec/internal/core"
	promptdata "github.com/noeljackson/deepsec/internal/processor/prompts"
)

type PatchFalsePositive struct {
	TaskID  string `json:"task_id"`
	File    string `json:"file"`
	Line    int    `json:"line"`
	Snippet string `json:"snippet,omitempty"`
	Matched string `json:"matched,omitempty"`
}

type PatchFalseNegative struct {
	TaskID           string   `json:"task_id"`
	IssueID          string   `json:"issue_id"`
	File             string   `json:"file"`
	StartLine        int      `json:"start_line"`
	EndLine          int      `json:"end_line"`
	VulnSlugs        []string `json:"vuln_slugs"`
	ClosestCandidate string   `json:"closest_candidate,omitempty"`
	Reason           string   `json:"reason"`
}

type Patch struct {
	Decision           string   `json:"decision"`
	SuppressPattern    string   `json:"suppress_pattern,omitempty"`
	RequireContent     string   `json:"require_content,omitempty"`
	FilePatterns       []string `json:"file_patterns,omitempty"`
	RequiresTech       []string `json:"requires_tech,omitempty"`
	AstLanguage        string   `json:"ast_language,omitempty"`
	AstQuery           string   `json:"ast_query,omitempty"`
	AstPrefilter       string   `json:"ast_prefilter,omitempty"`
	NeedsEngineFeature bool     `json:"-"`
	Rationale          string   `json:"rationale,omitempty"`
	Reason             string   `json:"reason,omitempty"`
}

type PatchJSONBackend interface {
	ProposePatchJSON(ctx context.Context, system, user string, schema json.RawMessage) (string, core.Usage, float64, error)
}

var PatchSchema = mustJSON(map[string]any{
	"type":                 "object",
	"additionalProperties": false,
	"required":             []string{"decision"},
	"properties": map[string]any{
		"decision":         map[string]any{"type": "string", "enum": []string{"suppress_pattern", "require_content", "file_patterns", "requires_tech", "ast_pattern", "needs-engine-feature"}},
		"suppress_pattern": map[string]any{"type": "string"},
		"require_content":  map[string]any{"type": "string"},
		"file_patterns":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"requires_tech":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"ast_language":     map[string]any{"type": "string", "enum": []string{"go", "typescript", "tsx", "javascript", "jsx", "python", "rust", "java"}},
		"ast_query":        map[string]any{"type": "string"},
		"ast_prefilter":    map[string]any{"type": "string"},
		"rationale":        map[string]any{"type": "string"},
		"reason":           map[string]any{"type": "string"},
	},
})

func ProposePatch(ctx context.Context, backend AgentBackend, slug string, fps []PatchFalsePositive, fns []PatchFalseNegative, currentMatcher string) (Patch, error) {
	if strings.TrimSpace(slug) == "" {
		return Patch{}, errors.New("empty slug")
	}
	system, user, err := buildPatchPrompt(slug, fps, fns, currentMatcher)
	if err != nil {
		return Patch{}, err
	}
	if raw, ok := backend.(PatchJSONBackend); ok {
		body, _, _, err := raw.ProposePatchJSON(ctx, system, core.RedactSecrets(user), PatchSchema)
		if err != nil {
			return Patch{}, err
		}
		return ParsePatch(body)
	}
	out, err := backend.Investigate(ctx, &InvestigateBatch{
		ProjectRoot: ".",
		Files: []InvestigateFile{{
			Path:    "matcher.toml",
			Content: core.RedactSecrets(currentMatcher),
		}},
		ProjectInfo:  "bounded matcher-patch proposal",
		PromptAppend: system + "\n\n" + core.RedactSecrets(user),
		SlugNotes:    []string{slug},
	})
	if err != nil {
		return Patch{}, err
	}
	if out.Refusal != nil {
		return Patch{}, fmt.Errorf("proposer refusal: %s", out.Refusal.Reason)
	}
	for _, r := range out.Results {
		for _, f := range r.Findings {
			if f.Description != "" {
				return ParsePatch(f.Description)
			}
		}
	}
	return Patch{}, errors.New("proposer returned no patch JSON")
}

func ParsePatch(body string) (Patch, error) {
	if extracted := ExtractJSON(body); extracted != "" {
		body = extracted
	}
	var p Patch
	if err := decodeStrict(body, &p); err != nil {
		return Patch{}, fmt.Errorf("patch schema: %w", err)
	}
	if err := p.Validate(); err != nil {
		return Patch{}, err
	}
	return p, nil
}

func (p *Patch) Validate() error {
	p.Decision = strings.TrimSpace(p.Decision)
	p.SuppressPattern = strings.TrimSpace(p.SuppressPattern)
	p.RequireContent = strings.TrimSpace(p.RequireContent)
	p.AstLanguage = strings.TrimSpace(p.AstLanguage)
	p.AstQuery = strings.TrimSpace(p.AstQuery)
	p.AstPrefilter = strings.TrimSpace(p.AstPrefilter)
	p.Rationale = strings.TrimSpace(p.Rationale)
	p.Reason = strings.TrimSpace(p.Reason)
	p.FilePatterns = trimNonEmpty(p.FilePatterns)
	p.RequiresTech = trimNonEmpty(p.RequiresTech)
	p.NeedsEngineFeature = p.Decision == "needs-engine-feature"
	// A patch field that *belongs* to a different decision is a model
	// confusion — fail loud rather than silently ignoring.
	noAst := p.AstLanguage == "" && p.AstQuery == "" && p.AstPrefilter == ""
	switch p.Decision {
	case "suppress_pattern":
		return requireOnly(p.SuppressPattern != "", len(p.FilePatterns) == 0, p.RequireContent == "", len(p.RequiresTech) == 0, noAst)
	case "require_content":
		return requireOnly(p.RequireContent != "", len(p.FilePatterns) == 0, p.SuppressPattern == "", len(p.RequiresTech) == 0, noAst)
	case "file_patterns":
		return requireOnly(len(p.FilePatterns) > 0, p.SuppressPattern == "", p.RequireContent == "", len(p.RequiresTech) == 0, noAst)
	case "requires_tech":
		return requireOnly(len(p.RequiresTech) > 0, p.SuppressPattern == "", p.RequireContent == "", len(p.FilePatterns) == 0, noAst)
	case "ast_pattern":
		if p.AstLanguage == "" {
			return errors.New("ast_pattern requires ast_language")
		}
		if p.AstQuery == "" {
			return errors.New("ast_pattern requires ast_query")
		}
		return requireOnly(true, p.SuppressPattern == "", p.RequireContent == "", len(p.FilePatterns) == 0, len(p.RequiresTech) == 0)
	case "needs-engine-feature":
		if p.Reason == "" {
			return errors.New("needs-engine-feature requires reason")
		}
		return requireOnly(true, p.SuppressPattern == "", p.RequireContent == "", len(p.FilePatterns) == 0, len(p.RequiresTech) == 0, noAst)
	default:
		return fmt.Errorf("unsupported patch decision %q", p.Decision)
	}
}

func (p Patch) Summary() string {
	switch p.Decision {
	case "suppress_pattern":
		return "added suppress_pattern " + p.SuppressPattern
	case "require_content":
		return "added require_content " + p.RequireContent
	case "file_patterns":
		return "tightened file_patterns to " + strings.Join(p.FilePatterns, ", ")
	case "requires_tech":
		return "added requires.tech " + strings.Join(p.RequiresTech, ", ")
	case "ast_pattern":
		return "added " + p.AstLanguage + " AST pattern"
	case "needs-engine-feature":
		return "needs engine feature: " + p.Reason
	}
	return p.Decision
}

func buildPatchPrompt(slug string, fps []PatchFalsePositive, fns []PatchFalseNegative, currentMatcher string) (string, string, error) {
	payload := struct {
		Slug           string               `json:"slug"`
		FalsePositives []PatchFalsePositive `json:"false_positives"`
		FalseNegatives []PatchFalseNegative `json:"false_negatives"`
		CurrentMatcher string               `json:"current_matcher"`
	}{slug, fps, fns, currentMatcher}
	body, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return "", "", err
	}
	return promptdata.AgentPrompt(), string(body), nil
}

func requireOnly(primary bool, rest ...bool) error {
	if !primary {
		return errors.New("patch decision missing required field")
	}
	for _, ok := range rest {
		if !ok {
			return errors.New("patch decision sets fields outside its decision")
		}
	}
	return nil
}

func trimNonEmpty(xs []string) []string {
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		x = strings.TrimSpace(x)
		if x != "" {
			out = append(out, x)
		}
	}
	return out
}
