package core

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAssertSafeSegmentRejectsTraversal(t *testing.T) {
	require.Error(t, AssertSafeSegment("..", "projectId"))
	require.Error(t, AssertSafeSegment("a/b", "projectId"))
	require.Error(t, AssertSafeSegment("", "projectId"))
	require.Error(t, AssertSafeSegment(".", "projectId"))
	require.NoError(t, AssertSafeSegment("ok", "projectId"))
}

func TestAssertSafeFilePath(t *testing.T) {
	require.NoError(t, AssertSafeFilePath("src/foo.ts"))
	require.Error(t, AssertSafeFilePath("../etc/passwd"))
	require.Error(t, AssertSafeFilePath("/abs"))
	require.Error(t, AssertSafeFilePath(`a\b`))
	require.Error(t, AssertSafeFilePath(""))
	require.Error(t, AssertSafeFilePath("src//foo.ts"))
}

func TestFileRecordPathAppendsJSON(t *testing.T) {
	r := DataRootFromPath("data")
	p, err := r.FileRecordPath("p", "src/x.ts")
	require.NoError(t, err)
	require.True(t, strings.HasSuffix(p, "data/p/files/src/x.ts.json"))
}

func TestFileRecordPathRejectsUnsafeSegments(t *testing.T) {
	r := DataRootFromPath("data")
	_, err := r.FileRecordPath("p", "../etc/passwd")
	require.Error(t, err)
	_, err = r.FileRecordPath("p", "/abs")
	require.Error(t, err)
	_, err = r.FileRecordPath("..", "x.ts")
	require.Error(t, err)
}

func TestReportPathsCarryRunID(t *testing.T) {
	r := DataRootFromPath("data")
	p, err := r.ReportJSONPath("p", "20260101000000-aaaa")
	require.NoError(t, err)
	require.True(t, strings.HasSuffix(p, "report-20260101000000-aaaa.json"))
	p, err = r.ReportMDPath("p", "")
	require.NoError(t, err)
	require.True(t, strings.HasSuffix(p, "report.md"))
}
