//! Resolve a set of relative file paths from CLI flags. Used by
//! `scan --diff` / `--files` / `--files-from` and the equivalent
//! `process` flags.

use anyhow::{Context, Result, anyhow};
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone)]
pub struct FileSourceArgs<'a> {
    pub files: Option<&'a [String]>,
    pub files_from: Option<&'a Path>,
    pub diff: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub struct ResolvedFiles {
    pub files: Vec<String>,
    /// Human-readable label, e.g. "git-diff:origin/main" or "files:cli".
    pub source: String,
}

pub fn resolve(args: FileSourceArgs<'_>, repo_root: &Path) -> Result<Option<ResolvedFiles>> {
    let set = [
        args.files.is_some(),
        args.files_from.is_some(),
        args.diff.is_some(),
    ];
    let count = set.iter().filter(|b| **b).count();
    if count == 0 {
        return Ok(None);
    }
    if count > 1 {
        return Err(anyhow!(
            "--files / --files-from / --diff are mutually exclusive"
        ));
    }
    if let Some(list) = args.files {
        return Ok(Some(ResolvedFiles {
            files: clean(list.iter().cloned()),
            source: "files:cli".into(),
        }));
    }
    if let Some(path) = args.files_from {
        let lines = read_files_from(path)?;
        return Ok(Some(ResolvedFiles {
            source: format!(
                "files-from:{}",
                if path == Path::new("-") {
                    "-".into()
                } else {
                    path.display().to_string()
                }
            ),
            files: clean(lines),
        }));
    }
    if let Some(spec) = args.diff {
        let files = git_diff_files(repo_root, spec)?;
        return Ok(Some(ResolvedFiles {
            source: format!("git-diff:{spec}"),
            files,
        }));
    }
    Ok(None)
}

fn clean<I: IntoIterator<Item = String>>(it: I) -> Vec<String> {
    let mut out: Vec<String> = it
        .into_iter()
        .map(|s| s.trim().replace('\\', "/"))
        .filter(|s| !s.is_empty())
        .collect();
    out.sort();
    out.dedup();
    out
}

fn read_files_from(path: &Path) -> Result<Vec<String>> {
    if path == Path::new("-") {
        let stdin = std::io::stdin();
        let reader = BufReader::new(stdin.lock());
        return Ok(reader
            .lines()
            .filter_map(|l| l.ok())
            .collect());
    }
    let body = fs_err::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    Ok(body.lines().map(str::to_string).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn cli<'a>(items: &'a [&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn no_flags_returns_none() {
        let r = resolve(
            FileSourceArgs {
                files: None,
                files_from: None,
                diff: None,
            },
            Path::new("/tmp"),
        )
        .unwrap();
        assert!(r.is_none());
    }

    #[test]
    fn files_dedupes_and_normalizes() {
        let v = cli(&["src/a.ts", "src/a.ts", "src/b.ts", "  ", "src\\c.ts"]);
        let r = resolve(
            FileSourceArgs {
                files: Some(&v),
                files_from: None,
                diff: None,
            },
            Path::new("/tmp"),
        )
        .unwrap()
        .unwrap();
        assert_eq!(r.source, "files:cli");
        assert_eq!(r.files, vec!["src/a.ts", "src/b.ts", "src/c.ts"]);
    }

    #[test]
    fn mutually_exclusive_flags_error() {
        let v = cli(&["a"]);
        let p = PathBuf::from("/tmp/list");
        let e = resolve(
            FileSourceArgs {
                files: Some(&v),
                files_from: Some(&p),
                diff: None,
            },
            Path::new("/tmp"),
        );
        assert!(e.is_err());
    }

    #[test]
    fn files_from_reads_a_file() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("list.txt");
        fs_err::write(&p, "src/a.ts\nsrc/b.ts\n").unwrap();
        let r = resolve(
            FileSourceArgs {
                files: None,
                files_from: Some(&p),
                diff: None,
            },
            Path::new("/tmp"),
        )
        .unwrap()
        .unwrap();
        assert!(r.source.starts_with("files-from:"));
        assert_eq!(r.files, vec!["src/a.ts", "src/b.ts"]);
    }

    #[test]
    fn diff_against_missing_ref_errors() {
        let d = tempfile::tempdir().unwrap();
        // No git repo here, so `git diff <bogus>` will fail.
        let e = resolve(
            FileSourceArgs {
                files: None,
                files_from: None,
                diff: Some("definitely-not-a-real-ref"),
            },
            d.path(),
        );
        assert!(e.is_err());
    }
}

fn git_diff_files(repo_root: &Path, spec: &str) -> Result<Vec<String>> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .arg("diff")
        .arg("--name-only")
        .arg("--diff-filter=ACMR")
        .arg(spec)
        .output()
        .context("running git diff")?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(anyhow!("git diff {spec}: {err}"));
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    Ok(clean(stdout.lines().map(str::to_string)))
}
