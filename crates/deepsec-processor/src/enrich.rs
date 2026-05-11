//! Git enrichment: populate `FileRecord.gitInfo.recentCommitters` by
//! shelling out to `git log`. The ownership oracle integration is left
//! as a plugin hook for callers that have one.

use crate::errors::ProcessorError;
use deepsec_core::ids::now_iso;
use deepsec_core::store::{load_all_file_records, write_file_record};
use deepsec_core::{DataRoot, GitCommitter, GitInfo};
use std::path::{Path, PathBuf};
use std::process::Command;

pub struct EnrichOptions {
    pub project_id: String,
    pub project_root: PathBuf,
    pub data_root: DataRoot,
    pub filter_prefix: Option<String>,
    pub max_committers: usize,
    pub force: bool,
}

#[derive(Debug, Default, Clone)]
pub struct EnrichOutcome {
    pub files_enriched: usize,
    pub files_skipped: usize,
}

pub fn run_enrich(opts: EnrichOptions) -> Result<EnrichOutcome, ProcessorError> {
    if !opts.project_root.join(".git").exists() {
        return Err(ProcessorError::Config(format!(
            "{} is not a git repository",
            opts.project_root.display()
        )));
    }

    let records = load_all_file_records(&opts.data_root, &opts.project_id)?;
    let mut outcome = EnrichOutcome::default();

    for mut rec in records {
        if let Some(prefix) = &opts.filter_prefix {
            if !rec.file_path.starts_with(prefix) {
                continue;
            }
        }
        if !opts.force && rec.git_info.is_some() {
            outcome.files_skipped += 1;
            continue;
        }
        let committers = recent_committers(
            &opts.project_root,
            Path::new(&rec.file_path),
            opts.max_committers,
        );
        rec.git_info = Some(GitInfo {
            recent_committers: committers,
            enriched_at: now_iso(),
            ownership: rec.git_info.and_then(|g| g.ownership),
        });
        write_file_record(&opts.data_root, &rec)?;
        outcome.files_enriched += 1;
    }
    Ok(outcome)
}

fn recent_committers(repo: &Path, file: &Path, max: usize) -> Vec<GitCommitter> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .arg("log")
        .arg(format!("-{}", max.max(1)))
        .arg("--pretty=format:%an%x09%ae%x09%aI")
        .arg("--")
        .arg(file)
        .output();
    let Ok(out) = out else {
        return Vec::new();
    };
    if !out.status.success() {
        return Vec::new();
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    stdout
        .lines()
        .filter_map(|line| {
            let mut parts = line.splitn(3, '\t');
            let name = parts.next()?.to_string();
            let email = parts.next()?.to_string();
            let date = parts.next()?.to_string();
            Some(GitCommitter { name, email, date })
        })
        .collect()
}
