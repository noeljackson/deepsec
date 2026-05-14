package bench

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func writeTaskToml(t *testing.T, dir, body string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "task.toml"), []byte(body), 0o644))
}

func TestLoadTaskConfigAcceptsFullProvenance(t *testing.T) {
	dir := t.TempDir()
	writeTaskToml(t, dir, `
[provenance]
source     = "codex-cyber"
source_url = "https://example.invalid/finding/1"
added_at   = "2026-05-13"
reviewer   = "@noeljackson"
review_due = "2026-08-13"

[labels]
change_rule = "external-disagreement-opens-issue"
`)
	cfg, err := loadTaskConfig(filepath.Join(dir, "task.toml"))
	require.NoError(t, err)
	require.Equal(t, "codex-cyber", cfg.Provenance.Source)
	require.Equal(t, "external-disagreement-opens-issue", cfg.Labels.ChangeRule)
}

func TestLoadTaskConfigRejectsMissingFields(t *testing.T) {
	cases := map[string]string{
		"missing-source": `[provenance]
added_at = "2026-05-13"
reviewer = "@x"
review_due = "2026-08-13"`,
		"missing-added_at": `[provenance]
source = "handcraft"
reviewer = "@x"
review_due = "2026-08-13"`,
		"missing-reviewer": `[provenance]
source = "handcraft"
added_at = "2026-05-13"
review_due = "2026-08-13"`,
		"missing-review_due": `[provenance]
source = "handcraft"
added_at = "2026-05-13"
reviewer = "@x"`,
		"bad-date": `[provenance]
source = "handcraft"
added_at = "13-05-2026"
reviewer = "@x"
review_due = "2026-08-13"`,
		"non-handcraft-missing-url": `[provenance]
source = "codex-cyber"
added_at = "2026-05-13"
reviewer = "@x"
review_due = "2026-08-13"`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeTaskToml(t, dir, body)
			_, err := loadTaskConfig(filepath.Join(dir, "task.toml"))
			require.Error(t, err, "expected validation error for %s", name)
		})
	}
}

func TestLoadTaskConfigRejectsBadChangeRule(t *testing.T) {
	dir := t.TempDir()
	writeTaskToml(t, dir, `
[provenance]
source     = "handcraft"
added_at   = "2026-05-13"
reviewer   = "@x"
review_due = "2026-08-13"

[labels]
change_rule = "whatever"
`)
	_, err := loadTaskConfig(filepath.Join(dir, "task.toml"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "change_rule")
}

func TestStaleTasksReportsOverdue(t *testing.T) {
	tasks := t.TempDir()
	writeTaskToml(t, filepath.Join(tasks, "fresh"), `
[provenance]
source     = "handcraft"
added_at   = "2026-05-13"
reviewer   = "@a"
review_due = "2027-05-13"
`)
	writeTaskToml(t, filepath.Join(tasks, "stale"), `
[provenance]
source     = "handcraft"
added_at   = "2024-01-01"
reviewer   = "@b"
review_due = "2024-04-01"
`)
	require.NoError(t, os.MkdirAll(filepath.Join(tasks, "fresh", "source"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(tasks, "stale", "source"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(tasks, "fresh", "answer.yaml"), []byte("issues: []\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(tasks, "stale", "answer.yaml"), []byte("issues: []\n"), 0o644))

	stale, err := StaleTasks(tasks, time.Date(2026, 5, 14, 0, 0, 0, 0, time.UTC))
	require.NoError(t, err)
	require.Len(t, stale, 1)
	require.Equal(t, "stale", stale[0].TaskID)
	require.Equal(t, "@b", stale[0].Reviewer)
	require.True(t, stale[0].OverdueBy > 0)
}
