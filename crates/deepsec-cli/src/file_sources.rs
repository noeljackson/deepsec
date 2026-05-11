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
