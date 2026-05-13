package scanner

import (
	"path/filepath"
	"regexp"
	"strings"
)

// taintSourcePatterns is the per-language allowlist of regex patterns
// that mark a line as containing an untrusted-input source. A matcher
// with `require_taint_within: N > 0` only fires within N lines of a
// tainted line. The patterns intentionally over-tag — false positives
// here cost recall, not precision; the AI investigation stage is the
// definitive verdict on whether a candidate is real.
//
// Sources for a language are matched against every line in a file with
// that language's extension; for unknown languages, the generic union
// in `taintSourceGeneric` applies.
var taintSourcePatterns = map[string][]*regexp.Regexp{
	"go": mustRegexes(
		`\br\s*\.URL\s*\.Query\s*\(`,
		`\br\s*\.Form\b`,
		`\br\s*\.PostForm\b`,
		`\br\s*\.Header\s*\.Get\s*\(`,
		`\br\s*\.Body\b`,
		`\brequest\s*\.URL\s*\.Query\s*\(`,
		`\bflag\s*\.(?:Arg|Args|String|Bool|Int|Float64)\s*\(`,
		`\bos\s*\.Args\b`,
		`\bos\s*\.Getenv\s*\(`,
	),
	"typescript": mustRegexes(
		`\breq\s*\.(?:body|query|params|headers|cookies|url)\b`,
		`\brequest\s*\.(?:body|query|params|headers|cookies|url)\b`,
		`\bctx\s*\.(?:request|req|params|query)\b`,
		`\bprocess\s*\.env\b`,
		`\bprocess\s*\.argv\b`,
		`\blocation\s*\.(?:search|hash|pathname|href)\b`,
		`\bwindow\s*\.location\b`,
	),
	"javascript": mustRegexes(
		`\breq\s*\.(?:body|query|params|headers|cookies|url)\b`,
		`\brequest\s*\.(?:body|query|params|headers|cookies|url)\b`,
		`\bprocess\s*\.env\b`,
		`\bprocess\s*\.argv\b`,
		`\blocation\s*\.(?:search|hash|pathname|href)\b`,
	),
	"python": mustRegexes(
		`\brequest\s*\.(?:args|form|json|values|cookies|headers|data|files)\b`,
		`\bos\s*\.environ\b`,
		`\bos\s*\.getenv\s*\(`,
		`\bsys\s*\.argv\b`,
		`\binput\s*\(`,
		`\bflask\.request\b`,
	),
	"ruby": mustRegexes(
		`\bparams\s*\[`,
		`\brequest\s*\.(?:parameters|env|headers|cookies)\b`,
		`\bENV\s*\[`,
		`\bARGV\b`,
	),
	"java": mustRegexes(
		`\.getParameter\s*\(`,
		`\.getHeader\s*\(`,
		`\.getQueryString\s*\(`,
		`\.getInputStream\s*\(`,
		`\.getReader\s*\(`,
		`@RequestParam\b`,
		`@RequestBody\b`,
		`@PathVariable\b`,
		`@RequestHeader\b`,
		`System\s*\.getenv\s*\(`,
	),
	"kotlin": mustRegexes(
		`\.getParameter\s*\(`,
		`\.getHeader\s*\(`,
		`@RequestParam\b`,
		`@RequestBody\b`,
		`@PathVariable\b`,
		`System\s*\.getenv\s*\(`,
		`\bintent\s*\.(?:getStringExtra|getData|extras)\b`,
	),
	"rust": mustRegexes(
		`\bweb::Path\s*<`,
		`\bweb::Query\s*<`,
		`\bweb::Json\s*<`,
		`\bweb::Form\s*<`,
		`\bJson\s*<`,
		`\bForm\s*<`,
		`\bQuery\s*<`,
		`\bPath\s*<`,
		`\benv::args\s*\(`,
		`\benv::var\s*\(`,
		`\breq\s*\.headers\s*\(`,
	),
	"php": mustRegexes(
		`\$_GET\s*\[`,
		`\$_POST\s*\[`,
		`\$_REQUEST\s*\[`,
		`\$_COOKIE\s*\[`,
		`\$_SERVER\s*\[`,
		`\$_FILES\s*\[`,
		`getenv\s*\(`,
	),
	"swift": mustRegexes(
		`URLComponents\s*\(`,
		`\.queryItems\b`,
		`\bProcessInfo\s*\.processInfo\s*\.environment\b`,
		`CommandLine\.arguments\b`,
		`UserDefaults\s*\.`,
	),
	"csharp": mustRegexes(
		`\.Request\s*\.(?:Query|Form|Headers|Cookies|Body)\b`,
		`\[FromBody\]`,
		`\[FromQuery\]`,
		`\[FromRoute\]`,
		`Environment\s*\.GetEnvironmentVariable\s*\(`,
	),
}

// taintSourceGeneric is applied to files whose language isn't in the
// per-language map. Union of the commonest patterns above so unknown
// extensions still get some coverage.
var taintSourceGeneric = mustRegexes(
	`\breq\s*\.(?:body|query|params|headers|cookies)\b`,
	`\brequest\s*\.(?:args|form|json|parameters|getParameter)\b`,
	`\.getenv\s*\(`,
	`\bos\s*\.environ\b`,
	`\bENV\s*\[`,
	`\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\s*\[`,
	`@RequestParam\b`,
	`@RequestBody\b`,
)

// taintLanguageForPath returns the language key used by
// taintSourcePatterns for the given file path, or empty for unknown.
func taintLanguageForPath(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".go":
		return "go"
	case ".ts", ".tsx":
		return "typescript"
	case ".js", ".jsx", ".mjs", ".cjs":
		return "javascript"
	case ".py":
		return "python"
	case ".rb":
		return "ruby"
	case ".java":
		return "java"
	case ".kt", ".kts":
		return "kotlin"
	case ".rs":
		return "rust"
	case ".php":
		return "php"
	case ".swift":
		return "swift"
	case ".cs":
		return "csharp"
	default:
		return ""
	}
}

// taintedLines returns the set of 1-based line numbers in `content`
// containing at least one taint source for the language detected from
// `filePath`. Returns nil if no taint sources match.
func taintedLines(content, filePath string) map[int]struct{} {
	patterns := taintSourceGeneric
	if lang := taintLanguageForPath(filePath); lang != "" {
		if langPatterns, ok := taintSourcePatterns[lang]; ok {
			patterns = langPatterns
		}
	}
	out := map[int]struct{}{}
	for lineIdx, line := range strings.Split(content, "\n") {
		for _, p := range patterns {
			if p.MatchString(line) {
				out[lineIdx+1] = struct{}{}
				break
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// lineWithinTaint reports whether `line` is within `radius` lines of
// any tainted line. A `tainted` map of length 0 always returns false
// (no sources → reject).
func lineWithinTaint(line, radius int, tainted map[int]struct{}) bool {
	if len(tainted) == 0 || radius <= 0 {
		return false
	}
	for offset := -radius; offset <= radius; offset++ {
		if _, ok := tainted[line+offset]; ok {
			return true
		}
	}
	return false
}

func mustRegexes(patterns ...string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		out = append(out, regexp.MustCompile(p))
	}
	return out
}
