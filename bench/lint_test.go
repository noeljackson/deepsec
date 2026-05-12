package bench

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLintMatchersCatchesProblems(t *testing.T) {
	dir := t.TempDir()
	err := os.WriteFile(filepath.Join(dir, "bad.toml"), []byte(`
[[matcher]]
slug = "dup"
description = "first"
noise_tier = "noisy"
file_patterns = ["**/*"]
patterns = ["foo(?=bar)"]

[[matcher]]
slug = "dup"
description = "second"
file_patterns = ["**/*.go"]
patterns = ["(foo)\\1", "["]
`), 0o644)
	require.NoError(t, err)

	findings, err := LintMatchers(dir)
	require.NoError(t, err)
	require.True(t, HasLintErrors(findings))
	requireFinding(t, findings, "duplicate-slug")
	requireFinding(t, findings, "patterns-unsupported-regex")
	requireFinding(t, findings, "patterns-invalid-regex")
	requireFinding(t, findings, "noisy-without-gate")
	requireFinding(t, findings, "overbroad-file-patterns")
}

func requireFinding(t *testing.T, findings []LintFinding, check string) {
	t.Helper()
	for _, f := range findings {
		if f.Check == check {
			return
		}
	}
	t.Fatalf("missing lint finding %q in %#v", check, findings)
}
