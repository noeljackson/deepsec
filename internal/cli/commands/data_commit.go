package commands

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/noeljackson/deepsec/internal/cli"
	"github.com/spf13/cobra"
)

// NewDataCommitCmd does `git add data/ && git commit`.
func NewDataCommitCmd(loader func() (*cli.Context, error)) *cobra.Command {
	var message, repo string
	var paths []string
	var allowEmpty bool
	cmd := &cobra.Command{
		Use:   "data-commit",
		Short: "git add data/ + git commit",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, err := loader()
			if err != nil {
				return err
			}
			repoPath := repo
			if repoPath == "" {
				if ctx.ConfigPath != "" {
					repoPath = filepath.Dir(ctx.ConfigPath)
				} else {
					repoPath = ctx.CWD
				}
			}
			if _, err := os.Stat(filepath.Join(repoPath, ".git")); err != nil {
				return fmt.Errorf("%s is not a git repository", repoPath)
			}

			addArgs := []string{"-C", repoPath, "add", "--"}
			if len(paths) > 0 {
				addArgs = append(addArgs, paths...)
			} else {
				relData, err := filepath.Rel(repoPath, ctx.DataRoot.Path)
				if err != nil {
					relData = ctx.DataRoot.Path
				}
				addArgs = append(addArgs, relData)
			}
			if err := exec.Command("git", addArgs...).Run(); err != nil {
				return fmt.Errorf("git add: %w", err)
			}

			diff := exec.Command("git", "-C", repoPath, "diff", "--cached", "--quiet")
			if err := diff.Run(); err == nil {
				if allowEmpty {
					fmt.Println("data-commit: nothing to commit")
					return nil
				}
				return fmt.Errorf("no changes staged")
			}

			if message == "" {
				message = fmt.Sprintf("deepsec: update %s (%s)",
					ctx.DataRoot.Path,
					time.Now().UTC().Format(time.RFC3339))
			}
			commit := exec.Command("git", "-C", repoPath, "commit", "-m", message)
			commit.Stdout = os.Stdout
			commit.Stderr = os.Stderr
			if err := commit.Run(); err != nil {
				return fmt.Errorf("git commit: %w", err)
			}
			fmt.Printf("data-commit %s\n", message)
			return nil
		},
	}
	cmd.Flags().StringVarP(&message, "message", "m", "", "Commit message")
	cmd.Flags().StringVar(&repo, "repo", "", "Repo path (default: config dir or cwd)")
	cmd.Flags().StringSliceVar(&paths, "paths", nil, "Paths to add (default: the entire data dir)")
	cmd.Flags().BoolVar(&allowEmpty, "allow-empty", false, "Exit cleanly when there's nothing to commit")
	return cmd
}
