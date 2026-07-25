package core

import "regexp"

// RedactedSecret is substituted for credential material before it is persisted
// in scan state or sent to an external investigator.
const RedactedSecret = "[REDACTED]"

var redactionPatterns = []struct {
	re          *regexp.Regexp
	replacement string
}{
	{regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`), RedactedSecret},
	{regexp.MustCompile(`\beyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\b`), RedactedSecret},
	{regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|sk-(?:proj-|live-|test-)?[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{35}|AKIA[0-9A-Z]{16})\b`), RedactedSecret},
	{regexp.MustCompile(`(?i)(\b(?:authorization|proxy-authorization)\s*[:=]\s*(?:bearer|basic)\s+)[^\s"',;]+`), `${1}` + RedactedSecret},
	{regexp.MustCompile("(?i)(\\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|secret(?:_value)?|password|private[_-]?key|credential|token|key)\\s*[:=]\\s*)(?:\\[REDACTED\\]|\\\"[^\\\"]*\\\"|'[^']*'|`[^`]*`|[^\\s,;)}\\]]+)"), `${1}` + RedactedSecret},
}

// RedactSecrets replaces common bearer, key, and password representations.
// It deliberately favors false positives over risking a secret leaving the
// local scanner boundary. It is idempotent so callers can apply it at every
// persistence and provider boundary.
func RedactSecrets(text string) string {
	for _, pattern := range redactionPatterns {
		text = pattern.re.ReplaceAllString(text, pattern.replacement)
	}
	return text
}

// RedactCandidate returns a storage-safe copy of a scanner candidate.
func RedactCandidate(candidate CandidateMatch) CandidateMatch {
	candidate.Snippet = RedactSecrets(candidate.Snippet)
	candidate.MatchedPattern = RedactSecrets(candidate.MatchedPattern)
	return candidate
}

// RedactFinding returns a storage-safe copy of an AI finding. Providers can
// echo source into titles, descriptions, and recommendations, so those fields
// must cross the same boundary as candidate snippets.
func RedactFinding(finding Finding) Finding {
	finding.Title = RedactSecrets(finding.Title)
	finding.Description = RedactSecrets(finding.Description)
	finding.Recommendation = RedactSecrets(finding.Recommendation)
	if finding.Triage != nil {
		copy := *finding.Triage
		copy.Reasoning = RedactSecrets(copy.Reasoning)
		finding.Triage = &copy
	}
	if finding.Revalidation != nil {
		copy := *finding.Revalidation
		copy.Reasoning = RedactSecrets(copy.Reasoning)
		finding.Revalidation = &copy
	}
	return finding
}

// RedactFileRecord returns a persistence-safe copy. Scan records collect
// model output over time, so sanitising only newly-created candidates is not
// sufficient: a later write must also clean records created by older versions.
func RedactFileRecord(record *FileRecord) *FileRecord {
	if record == nil {
		return nil
	}
	copy := *record
	copy.Candidates = make([]CandidateMatch, len(record.Candidates))
	for i, candidate := range record.Candidates {
		copy.Candidates[i] = RedactCandidate(candidate)
	}
	copy.Findings = make([]Finding, len(record.Findings))
	for i, finding := range record.Findings {
		copy.Findings[i] = RedactFinding(finding)
	}
	copy.AnalysisHistory = make([]AnalysisEntry, len(record.AnalysisHistory))
	for i, entry := range record.AnalysisHistory {
		entry.CodexStderr = RedactSecrets(entry.CodexStderr)
		if entry.Refusal != nil {
			refusal := *entry.Refusal
			refusal.Reason = RedactSecrets(refusal.Reason)
			refusal.Raw = RedactSecrets(refusal.Raw)
			refusal.Skipped = append([]RefusalSkipped(nil), refusal.Skipped...)
			for j := range refusal.Skipped {
				refusal.Skipped[j].Reason = RedactSecrets(refusal.Skipped[j].Reason)
			}
			entry.Refusal = &refusal
		}
		copy.AnalysisHistory[i] = entry
	}
	return &copy
}
