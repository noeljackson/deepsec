package bench

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/noeljackson/deepsec/internal/core"
	"github.com/stretchr/testify/require"
)

func TestLoadAnswerKeyValid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "answer.yaml")
	err := os.WriteFile(path, []byte(`
issues:
  - id: go-cmd-001
    file: main.go
    severity: HIGH
    cwe: CWE-78
    vulnSlugs: [command-injection, go-command-injection]
    location: { startLine: 10, endLine: 12, tolerance: 2 }
    scanner: { mustEmitCandidate: true }
decoys:
  - id: go-cmd-decoy
    file: main.go
    line: 20
    forbiddenSlugs: [command-injection]
`), 0o644)
	require.NoError(t, err)
	key, err := LoadAnswerKey(path)
	require.NoError(t, err)
	require.Len(t, key.Issues, 1)
	require.Equal(t, core.SeverityHigh, key.Issues[0].Severity)
	require.Len(t, key.Decoys, 1)
}

func TestLoadAnswerKeyInvalid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "answer.yaml")
	err := os.WriteFile(path, []byte(`
issues:
  - file: ../main.go
    severity: HIGH
    vulnSlugs: []
    location: { startLine: 2, endLine: 1 }
    scanner: { mustEmitCandidate: true }
`), 0o644)
	require.NoError(t, err)
	_, err = LoadAnswerKey(path)
	require.Error(t, err)
}

func TestToleranceBoundary(t *testing.T) {
	tol := 3
	loc := Location{StartLine: 12, EndLine: 18, Tolerance: &tol}
	require.True(t, loc.Contains(9))
	require.True(t, loc.Contains(21))
	require.False(t, loc.Contains(8))
	require.False(t, loc.Contains(22))
	require.Equal(t, DefaultTolerance, (Location{StartLine: 1, EndLine: 1}).ToleranceOrDefault())
}

func TestSlugAliasMatching(t *testing.T) {
	require.True(t, SlugMatches("server-side-request-forgery", []string{"ssrf", "server-side-request-forgery"}))
	require.False(t, SlugMatches("open-redirect", []string{"ssrf", "server-side-request-forgery"}))
}

func TestDecoyDetection(t *testing.T) {
	decoy := Decoy{File: "app.py", Line: 42, ForbiddenSlugs: []string{"ssrf"}}
	require.True(t, decoyMatches(decoy, candidateRef{File: "app.py", CandidateMatch: core.CandidateMatch{VulnSlug: "ssrf", LineNumbers: []int{42}}}))
	require.False(t, decoyMatches(decoy, candidateRef{File: "app.py", CandidateMatch: core.CandidateMatch{VulnSlug: "ssrf", LineNumbers: []int{43}}}))
	require.False(t, decoyMatches(decoy, candidateRef{File: "app.py", CandidateMatch: core.CandidateMatch{VulnSlug: "open-redirect", LineNumbers: []int{42}}}))
}
