package processor

import (
	"fmt"
	"sort"
	"strings"

	promptdata "github.com/noeljackson/deepsec/internal/processor/prompts"
)

// CorePrompt is the system-prompt preamble shared across backends. The
// JSON-output rules and finding schema are baked in so the response is
// machine-parseable.
var CorePrompt = promptdata.CorePrompt()

// AssemblePrompt builds the (system, user) pair for one investigation
// batch. The system prompt is stable across a run (good for prompt
// caching); the user prompt is per-batch.
func AssemblePrompt(b *InvestigateBatch) (system, user string) {
	var sys strings.Builder
	sys.WriteString(CorePrompt)

	highlights := make([]string, 0, len(b.TechTags))
	for _, t := range b.TechTags {
		if h := HighlightForTag(t); h != "" {
			highlights = append(highlights, h)
		}
	}
	if len(highlights) > 0 {
		sys.WriteString("\nFramework-specific context:\n")
		for _, h := range highlights {
			fmt.Fprintf(&sys, "- %s\n", h)
		}
	}

	if len(b.SlugNotes) > 0 {
		notes := uniqueSlugs(b.SlugNotes)
		hits := make([]string, 0, len(notes))
		for _, slug := range notes {
			if n := NoteForSlug(slug); n != "" {
				hits = append(hits, fmt.Sprintf("- %s: %s", slug, n))
			}
		}
		if len(hits) > 0 {
			sys.WriteString("\nCandidate-slug reasoning hints:\n")
			sys.WriteString(strings.Join(hits, "\n"))
			sys.WriteString("\n")
		}
	}

	if strings.TrimSpace(b.ProjectInfo) != "" {
		sys.WriteString("\nProject context:\n")
		sys.WriteString(strings.TrimSpace(b.ProjectInfo))
		sys.WriteString("\n")
	}
	if strings.TrimSpace(b.PromptAppend) != "" {
		sys.WriteString("\n")
		sys.WriteString(strings.TrimSpace(b.PromptAppend))
		sys.WriteString("\n")
	}

	var u strings.Builder
	u.WriteString("Review these files for exploitable vulnerabilities.\n\n")
	for _, f := range b.Files {
		fmt.Fprintf(&u, "===== FILE: %s =====\n", f.Path)
		if len(f.Candidates) > 0 {
			u.WriteString("Candidate matches (regex-derived, may be noisy):\n")
			for _, c := range f.Candidates {
				fmt.Fprintf(&u, "  - slug=%s lines=%v matched=%q\n", c.VulnSlug, c.LineNumbers, c.MatchedPattern)
			}
		}
		u.WriteString("Code:\n")
		for i, line := range strings.Split(f.Content, "\n") {
			fmt.Fprintf(&u, "%5d %s\n", i+1, line)
		}
		u.WriteString("\n")
	}
	u.WriteString("\nReport each genuine vulnerability via the structured output channel.")

	return sys.String(), u.String()
}

func uniqueSlugs(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// BuildRevalidatePrompt produces (system, user) for one revalidation call.
// When in.Skeptic is true, the system prompt is swapped for an adversarial
// "try to disprove this finding" stance; output shape is unchanged so
// the same RevalidatedFinding parsing applies.
func BuildRevalidatePrompt(in *RevalidateInput) (system, user string) {
	if in.Skeptic {
		system = `You are a skeptical security reviewer doing a second-pass audit. Each finding below was reported by a previous reviewer. Your job is to TRY TO DISPROVE each one: look for the sanitisation, the auth check, the unreachable path, the framework default that already protects this site. For each finding decide one of:
- "true-positive": you tried to disprove it and could not — the vulnerability holds up
- "false-positive": you found a concrete reason it does not exploit (specific sanitiser, auth gate, dead code)
- "fixed": the code already has the mitigation in place
- "uncertain": you cannot confidently disprove it but the evidence is thin — caller may demote severity

Be specific in "reasoning": name the sanitiser, the function, the line. Generic doubt is not enough to flip a true-positive. Return verdicts via the structured output channel. ` + "`adjustedSeverity`" + ` is optional and only set when you want to demote a finding whose original severity overstates the residual risk.`
	} else {
		system = `You are revalidating previously reported security findings against the CURRENT state of the file. For each finding decide one of:
- "true-positive": the vulnerability is still present and exploitable
- "false-positive": the original report was wrong
- "fixed": the code has been changed and the issue is no longer present
- "uncertain": you can't tell from this file alone

Return findings via the structured output channel. ` + "`adjustedSeverity`" + ` is optional and only set when you want to change the original severity.`
	}

	var u strings.Builder
	fmt.Fprintf(&u, "File: %s\nCode:\n", in.FilePath)
	for i, line := range strings.Split(in.FileContent, "\n") {
		fmt.Fprintf(&u, "%5d %s\n", i+1, line)
	}
	u.WriteString("\nFindings to revalidate:\n")
	for _, f := range in.Findings {
		fmt.Fprintf(&u, "[%d] severity=%s slug=%s lines=%v title=%s\n", f.Index, f.Severity, f.VulnSlug, f.LineNumbers, f.Title)
		fmt.Fprintf(&u, "    description: %s\n", f.Description)
	}
	return system, u.String()
}

// BuildTriagePrompt produces (system, user) for one triage call.
func BuildTriagePrompt(in *TriageInput) (system, user string) {
	system = `You are triaging one security finding. Assign:
- priority: "P0" (drop everything) | "P1" (this sprint) | "P2" (backlog) | "skip" (not worth fixing)
- exploitability: "trivial" | "moderate" | "difficult"
- impact: "critical" | "high" | "medium" | "low"
- reasoning: one short paragraph.

Return the triage via the structured output channel.`
	var u strings.Builder
	fmt.Fprintf(&u, "File: %s\n", in.FilePath)
	fmt.Fprintf(&u, "severity=%s slug=%s lines=%v title=%s\n", in.Finding.Severity, in.Finding.VulnSlug, in.Finding.LineNumbers, in.Finding.Title)
	fmt.Fprintf(&u, "description: %s\n", in.Finding.Description)
	return system, u.String()
}
