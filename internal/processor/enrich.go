package processor

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/noeljackson/deepsec/internal/core"
)

// EnrichOptions drives the git-committer enrichment pass.
type EnrichOptions struct {
	ProjectID     string
	ProjectRoot   string
	DataRoot      core.DataRoot
	FilterPrefix  string
	MaxCommitters int
	Force         bool
}

// EnrichOutcome summarizes the run.
type EnrichOutcome struct {
	FilesEnriched int
	FilesSkipped  int
}

// Enrich populates FileRecord.gitInfo.recentCommitters via `git log`.
// Files outside a git repo or with no matching log entries get nil.
func Enrich(opts EnrichOptions) (*EnrichOutcome, error) {
	if _, err := os.Stat(opts.ProjectRoot + "/.git"); err != nil {
		return nil, fmt.Errorf("%s is not a git repository", opts.ProjectRoot)
	}
	records, err := opts.DataRoot.LoadAllFileRecords(opts.ProjectID)
	if err != nil {
		return nil, err
	}
	out := &EnrichOutcome{}
	maxC := opts.MaxCommitters
	if maxC < 1 {
		maxC = 5
	}
	for _, rec := range records {
		if opts.FilterPrefix != "" && !hasPrefix(rec.FilePath, opts.FilterPrefix) {
			continue
		}
		if !opts.Force && rec.GitInfo != nil {
			out.FilesSkipped++
			continue
		}
		commits := recentCommitters(opts.ProjectRoot, rec.FilePath, maxC)
		gitInfo := &core.GitInfo{
			RecentCommitters: commits,
			EnrichedAt:       core.NowISO(),
		}
		if rec.GitInfo != nil {
			gitInfo.Ownership = rec.GitInfo.Ownership
		}
		rec.GitInfo = gitInfo
		if err := opts.DataRoot.WriteFileRecord(rec); err != nil {
			return nil, err
		}
		out.FilesEnriched++
	}
	return out, nil
}

func recentCommitters(repo, file string, max int) []core.GitCommitter {
	cmd := exec.Command("git",
		"-C", repo,
		"log",
		fmt.Sprintf("-%d", max),
		"--pretty=format:%an\t%ae\t%aI",
		"--", file,
	)
	body, err := cmd.Output()
	if err != nil {
		return nil
	}
	out := []core.GitCommitter{}
	for _, line := range strings.Split(string(body), "\n") {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "\t", 3)
		if len(parts) != 3 {
			continue
		}
		out = append(out, core.GitCommitter{
			Name:  parts[0],
			Email: parts[1],
			Date:  parts[2],
		})
	}
	return out
}
