package processor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	promptdata "github.com/noeljackson/deepsec/internal/processor/prompts"
)

// NewMatcher is the strict-JSON response from the recall proposer.
// Decisions:
//   - "new_matcher": propose a complete [[matcher]] TOML block in TOMLBody.
//   - "cannot-fix": no safe new matcher from the supplied FN cluster.
//   - "needs-engine-feature": current TOML/AST surface can't express the
//     pattern needed; reason explains what feature is missing.
type NewMatcher struct {
	Decision           string `json:"decision"`
	Slug               string `json:"slug,omitempty"`
	TOMLBody           string `json:"toml_body,omitempty"`
	Rationale          string `json:"rationale,omitempty"`
	Reason             string `json:"reason,omitempty"`
	NeedsEngineFeature bool   `json:"-"`
}

// The recall proposer uses the same strict-JSON backend method as the
// matcher patcher (ProposePatchJSON on PatchJSONBackend) — both want
// "send this system + user prompt, get back JSON conforming to the
// given schema." The method name predates the recall mode but the
// behaviour is generic. Anthropic and OpenAI-compatible backends both
// implement it.

var NewMatcherSchema = mustJSON(map[string]any{
	"type":                 "object",
	"additionalProperties": false,
	"required":             []string{"decision"},
	"properties": map[string]any{
		"decision":  map[string]any{"type": "string", "enum": []string{"new_matcher", "cannot-fix", "needs-engine-feature"}},
		"slug":      map[string]any{"type": "string"},
		"toml_body": map[string]any{"type": "string"},
		"rationale": map[string]any{"type": "string"},
		"reason":    map[string]any{"type": "string"},
	},
})

// RecallCluster groups false negatives the recall agent will try to
// turn into a new matcher.
type RecallCluster struct {
	VulnSlug       string
	FalseNegatives []PatchFalseNegative
}

func ProposeNewMatcher(ctx context.Context, backend AgentBackend, cluster RecallCluster, existingSlugs []string) (NewMatcher, error) {
	if strings.TrimSpace(cluster.VulnSlug) == "" {
		return NewMatcher{}, errors.New("empty vuln slug")
	}
	if len(cluster.FalseNegatives) == 0 {
		return NewMatcher{}, errors.New("empty false-negative cluster")
	}
	system, user, err := buildRecallPrompt(cluster, existingSlugs)
	if err != nil {
		return NewMatcher{}, err
	}
	if raw, ok := backend.(PatchJSONBackend); ok {
		body, _, _, err := raw.ProposePatchJSON(ctx, system, user, NewMatcherSchema)
		if err != nil {
			return NewMatcher{}, err
		}
		return ParseNewMatcher(body)
	}
	out, err := backend.Investigate(ctx, &InvestigateBatch{
		ProjectRoot: ".",
		Files: []InvestigateFile{{
			Path:    "recall.json",
			Content: user,
		}},
		ProjectInfo:  "bounded recall-proposal: propose one new matcher",
		PromptAppend: system + "\n\n" + user,
		SlugNotes:    []string{cluster.VulnSlug},
	})
	if err != nil {
		return NewMatcher{}, err
	}
	if out.Refusal != nil {
		return NewMatcher{}, fmt.Errorf("recall proposer refusal: %s", out.Refusal.Reason)
	}
	for _, r := range out.Results {
		for _, f := range r.Findings {
			if f.Description != "" {
				return ParseNewMatcher(f.Description)
			}
		}
	}
	return NewMatcher{}, errors.New("recall proposer returned no JSON")
}

func ParseNewMatcher(body string) (NewMatcher, error) {
	if extracted := ExtractJSON(body); extracted != "" {
		body = extracted
	}
	var m NewMatcher
	if err := decodeStrict(body, &m); err != nil {
		return NewMatcher{}, fmt.Errorf("new-matcher schema: %w", err)
	}
	if err := m.Validate(); err != nil {
		return NewMatcher{}, err
	}
	return m, nil
}

func (m *NewMatcher) Validate() error {
	m.Decision = strings.TrimSpace(m.Decision)
	m.Slug = strings.TrimSpace(m.Slug)
	m.TOMLBody = strings.TrimSpace(m.TOMLBody)
	m.Rationale = strings.TrimSpace(m.Rationale)
	m.Reason = strings.TrimSpace(m.Reason)
	m.NeedsEngineFeature = m.Decision == "needs-engine-feature"
	switch m.Decision {
	case "new_matcher":
		if m.Slug == "" {
			return errors.New("new_matcher requires slug")
		}
		if m.TOMLBody == "" {
			return errors.New("new_matcher requires toml_body")
		}
		if !strings.Contains(m.TOMLBody, "[[matcher]]") {
			return errors.New("new_matcher toml_body must contain [[matcher]]")
		}
		if !strings.Contains(m.TOMLBody, "slug") {
			return errors.New("new_matcher toml_body must declare slug")
		}
		return nil
	case "cannot-fix":
		if m.Reason == "" {
			return errors.New("cannot-fix requires reason")
		}
		return nil
	case "needs-engine-feature":
		if m.Reason == "" {
			return errors.New("needs-engine-feature requires reason")
		}
		return nil
	default:
		return fmt.Errorf("unsupported new-matcher decision %q", m.Decision)
	}
}

func (m NewMatcher) Summary() string {
	switch m.Decision {
	case "new_matcher":
		return fmt.Sprintf("propose new matcher %q", m.Slug)
	case "cannot-fix":
		return "cannot-fix: " + m.Reason
	case "needs-engine-feature":
		return "needs-engine-feature: " + m.Reason
	}
	return m.Decision
}

func buildRecallPrompt(cluster RecallCluster, existingSlugs []string) (string, string, error) {
	payload := struct {
		ClusterVulnSlug string               `json:"cluster_vuln_slug"`
		FalseNegatives  []PatchFalseNegative `json:"false_negatives"`
		ExistingSlugs   []string             `json:"existing_slugs"`
	}{cluster.VulnSlug, cluster.FalseNegatives, existingSlugs}
	body, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return "", "", err
	}
	return promptdata.RecallAgentPrompt(), string(body), nil
}
