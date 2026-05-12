package processor

import "encoding/json"

// FindingsSchema is the JSON Schema for the `report_findings` tool /
// `response_format: json_schema` we ask the model to produce. Strict
// shape: required fields, no additional properties.
var FindingsSchema = mustJSON(map[string]any{
	"type":                 "object",
	"additionalProperties": false,
	"required":             []string{"findings"},
	"properties": map[string]any{
		"refusal": map[string]any{
			"type":        "string",
			"description": "If set, no findings are reported and this is the reason.",
		},
		"findings": map[string]any{
			"type": "array",
			"items": map[string]any{
				"type":                 "object",
				"additionalProperties": false,
				"required":             []string{"filePath", "severity", "vulnSlug", "title", "description", "lineNumbers", "recommendation", "confidence"},
				"properties": map[string]any{
					"filePath":       map[string]any{"type": "string"},
					"severity":       map[string]any{"type": "string", "enum": []string{"CRITICAL", "HIGH", "MEDIUM", "HIGH_BUG", "BUG", "LOW"}},
					"vulnSlug":       map[string]any{"type": "string"},
					"title":          map[string]any{"type": "string"},
					"description":    map[string]any{"type": "string"},
					"lineNumbers":    map[string]any{"type": "array", "items": map[string]any{"type": "integer"}},
					"recommendation": map[string]any{"type": "string"},
					"confidence":     map[string]any{"type": "string", "enum": []string{"high", "medium", "low"}},
				},
			},
		},
	},
})

// RevalidateSchema for the `revalidate_findings` tool.
var RevalidateSchema = mustJSON(map[string]any{
	"type":                 "object",
	"additionalProperties": false,
	"required":             []string{"revalidations"},
	"properties": map[string]any{
		"revalidations": map[string]any{
			"type": "array",
			"items": map[string]any{
				"type":                 "object",
				"additionalProperties": false,
				"required":             []string{"index", "verdict", "reasoning"},
				"properties": map[string]any{
					"index":            map[string]any{"type": "integer"},
					"verdict":          map[string]any{"type": "string", "enum": []string{"true-positive", "false-positive", "fixed", "uncertain", "accepted-risk"}},
					"reasoning":        map[string]any{"type": "string"},
					"adjustedSeverity": map[string]any{"type": "string", "enum": []string{"CRITICAL", "HIGH", "MEDIUM", "HIGH_BUG", "BUG", "LOW"}},
				},
			},
		},
	},
})

// TriageSchema for the `triage_finding` tool.
var TriageSchema = mustJSON(map[string]any{
	"type":                 "object",
	"additionalProperties": false,
	"required":             []string{"priority", "exploitability", "impact", "reasoning"},
	"properties": map[string]any{
		"priority":       map[string]any{"type": "string", "enum": []string{"P0", "P1", "P2", "skip"}},
		"exploitability": map[string]any{"type": "string", "enum": []string{"trivial", "moderate", "difficult"}},
		"impact":         map[string]any{"type": "string", "enum": []string{"critical", "high", "medium", "low"}},
		"reasoning":      map[string]any{"type": "string"},
	},
})

// FindingsEnvelope is the deserialized response from the AI backends.
type FindingsEnvelope struct {
	Findings []EnvelopeFinding `json:"findings"`
	Refusal  string            `json:"refusal,omitempty"`
}

type EnvelopeFinding struct {
	FilePath       string `json:"filePath"`
	Severity       string `json:"severity"`
	VulnSlug       string `json:"vulnSlug"`
	Title          string `json:"title"`
	Description    string `json:"description"`
	LineNumbers    []int  `json:"lineNumbers"`
	Recommendation string `json:"recommendation"`
	Confidence     string `json:"confidence"`
}

// RevalidateEnvelope is the deserialized revalidation response.
type RevalidateEnvelope struct {
	Revalidations []RevalidatedFinding `json:"revalidations"`
	Refusal       string               `json:"refusal,omitempty"`
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// ExtractJSON returns a JSON object substring from text that may be
// wrapped in ```json ... ``` fences or have prose around it. Fallback
// for backends that don't support structured outputs natively.
func ExtractJSON(body string) string {
	const fence = "```json"
	if i := indexOf(body, fence); i >= 0 {
		rest := body[i+len(fence):]
		if j := indexOf(rest, "```"); j >= 0 {
			return trimSpace(rest[:j])
		}
	}
	if i := indexOf(body, "```"); i >= 0 {
		rest := body[i+3:]
		if j := indexOf(rest, "```"); j >= 0 {
			return trimSpace(rest[:j])
		}
	}
	first := indexOf(body, "{")
	last := lastIndexOf(body, "}")
	if first >= 0 && last > first {
		return trimSpace(body[first : last+1])
	}
	return ""
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func lastIndexOf(s, sub string) int {
	for i := len(s) - len(sub); i >= 0; i-- {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t' || s[0] == '\n' || s[0] == '\r') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t' || s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
