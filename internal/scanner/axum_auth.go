package scanner

import (
	"regexp"
	"strings"

	"github.com/noeljackson/deepsec/internal/core"
)

var (
	axumMutationRouteRE = regexp.MustCompile(`(?s)\.route\s*\(\s*"[^"]+"\s*,\s*(?:post|put|delete|patch)\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*\)`)
	axumAuthExtractorRE = regexp.MustCompile(`(?i)\b(?:authenticated|authentication|authcontext|authclaims|claims|principal|session|current_?user|identity)\b`)
	axumAuthCallRE      = regexp.MustCompile(`(?i)\b(?:require|verify|authorize|authenticate|ensure)[A-Za-z_]*\s*\(`)
)

// axumMutationRoutesWithoutAuth follows a same-file Axum mutation route to
// its handler and emits a candidate only when neither an auth extractor nor a
// plainly named authorization call is present. It is deliberately an audit
// candidate rather than a proof of an authorization bypass: Axum projects can
// enforce policy in middleware or a service layer, which source-local analysis
// cannot prove here.
func axumMutationRoutesWithoutAuth(content string) []core.CandidateMatch {
	lines := strings.Split(content, "\n")
	var out []core.CandidateMatch
	for _, route := range axumMutationRouteRE.FindAllStringSubmatchIndex(content, -1) {
		handler := content[route[2]:route[3]]
		line := 1 + strings.Count(content[:route[0]], "\n")
		fn := regexp.MustCompile(`(?s)(?:pub\s+)?async\s+fn\s+` + regexp.QuoteMeta(handler) + `\s*\((.*?)\)\s*(?:->[^\{]+)?\{`).FindStringSubmatchIndex(content)
		if fn != nil {
			args := content[fn[2]:fn[3]]
			bodyEnd := matchingRustBlockEnd(content, fn[1]-1)
			if axumAuthExtractorRE.MatchString(args) || axumAuthCallRE.MatchString(content[fn[1]:bodyEnd]) {
				continue
			}
		}
		out = append(out, core.CandidateMatch{
			VulnSlug:       "rust-axum-no-auth-extractor",
			LineNumbers:    []int{line},
			Snippet:        core.RedactSecrets(buildSnippet(lines, line, 2, 10)),
			MatchedPattern: "state-changing Axum route whose same-file handler has no recognized authorization boundary",
		})
	}
	return out
}

func matchingRustBlockEnd(content string, openingBrace int) int {
	depth := 0
	inString := byte(0)
	escaped := false
	for i := openingBrace; i < len(content); i++ {
		ch := content[i]
		if inString != 0 {
			if escaped {
				escaped = false
				continue
			}
			if ch == '\\' {
				escaped = true
				continue
			}
			if ch == inString {
				inString = 0
			}
			continue
		}
		if ch == '"' || ch == '\'' {
			inString = ch
			continue
		}
		switch ch {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return len(content)
}
