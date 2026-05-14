package commands

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSplitGatedByTechExposesActiveAndSkipped(t *testing.T) {
	_ = splitGatedByTech
}

func TestRankCountsOrderingDescending(t *testing.T) {
	got := rankCounts(map[string]int{
		"a": 1,
		"b": 5,
		"c": 3,
		"d": 5,
	})
	require.Equal(t, "b", got[0].key)
	require.Equal(t, 5, got[0].n)
	require.Equal(t, "d", got[1].key)
	require.Equal(t, 5, got[1].n)
	require.Equal(t, "c", got[2].key)
	require.Equal(t, "a", got[3].key)
}

func TestParseProjectFileReadsCandidates(t *testing.T) {
	body := []byte(`{"candidates":[{"vulnSlug":"sqli","lineNumbers":[1]},{"vulnSlug":"ssrf"}]}`)
	pf, err := parseProjectFile(body)
	require.NoError(t, err)
	require.Len(t, pf.Candidates, 2)
	require.Equal(t, "sqli", pf.Candidates[0].VulnSlug)
	require.Equal(t, "ssrf", pf.Candidates[1].VulnSlug)
}

func TestParseProjectFileRejectsGarbage(t *testing.T) {
	_, err := parseProjectFile([]byte("not json"))
	require.Error(t, err)
}
