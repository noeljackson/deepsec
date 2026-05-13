package regressions

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/noeljackson/deepsec/internal/scanner"
	"github.com/stretchr/testify/require"
)

func TestLoadMalformedTOMLErrorsClearly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.toml")
	require.NoError(t, os.WriteFile(path, []byte("[[case]\nslug = "), 0o644))

	_, err := Load(path)
	require.Error(t, err)
	require.Contains(t, err.Error(), "parse regression cases")
}

func TestRegressionCasesParseAndMatchExpectations(t *testing.T) {
	corpus, err := Load(filepath.Join("..", "regression_cases.toml"))
	require.NoError(t, err)
	require.NotEmpty(t, corpus.Cases)

	reg, err := scanner.WithBuiltin()
	require.NoError(t, err)
	for _, c := range corpus.Cases {
		t.Run(c.Slug+"/"+c.Expectation+"/"+c.SourceRef, func(t *testing.T) {
			m := reg.Get(c.Slug)
			require.NotNilf(t, m, "missing matcher %s", c.Slug)
			hits := m.Match(c.Content, c.FilePath)
			switch c.Expectation {
			case MustFire:
				require.NotEmpty(t, hits, c.Reason)
			case MustNotFire:
				require.Empty(t, hits, c.Reason)
			}
		})
	}
}
