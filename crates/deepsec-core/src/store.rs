use crate::ids::now_iso;
use crate::paths::{
    DataRoot, PathError, file_record_path, files_dir, project_config_path,
};
use crate::types::{FileRecord, ProjectConfig};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use thiserror::Error;
use walkdir::WalkDir;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("path error: {0}")]
    Path(#[from] PathError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

pub fn file_hash_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

pub fn ensure_project(
    root: &DataRoot,
    project_id: &str,
    root_path: &str,
    github_url: Option<&str>,
) -> Result<ProjectConfig, StoreError> {
    let path = project_config_path(root, project_id)?;
    if let Some(parent) = path.parent() {
        fs_err::create_dir_all(parent)?;
    }
    if path.exists() {
        let body = fs_err::read_to_string(&path)?;
        let cfg: ProjectConfig = serde_json::from_str(&body)?;
        return Ok(cfg);
    }
    let cfg = ProjectConfig {
        project_id: project_id.into(),
        root_path: root_path.into(),
        created_at: now_iso(),
        github_url: github_url.map(String::from),
    };
    fs_err::write(&path, serde_json::to_string_pretty(&cfg)?)?;
    Ok(cfg)
}

pub fn read_project_config(
    root: &DataRoot,
    project_id: &str,
) -> Result<Option<ProjectConfig>, StoreError> {
    let path = project_config_path(root, project_id)?;
    match fs_err::read_to_string(&path) {
        Ok(s) => Ok(Some(serde_json::from_str(&s)?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

pub fn write_project_config(
    root: &DataRoot,
    cfg: &ProjectConfig,
) -> Result<(), StoreError> {
    let path = project_config_path(root, &cfg.project_id)?;
    if let Some(parent) = path.parent() {
        fs_err::create_dir_all(parent)?;
    }
    fs_err::write(path, serde_json::to_string_pretty(cfg)?)?;
    Ok(())
}

pub fn read_file_record(
    root: &DataRoot,
    project_id: &str,
    file_path: &str,
) -> Result<Option<FileRecord>, StoreError> {
    let path = file_record_path(root, project_id, file_path)?;
    match fs_err::read_to_string(&path) {
        Ok(s) => Ok(Some(serde_json::from_str(&s)?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

pub fn write_file_record(root: &DataRoot, record: &FileRecord) -> Result<(), StoreError> {
    let path = file_record_path(root, &record.project_id, &record.file_path)?;
    if let Some(parent) = path.parent() {
        fs_err::create_dir_all(parent)?;
    }
    let body = serde_json::to_string_pretty(record)?;
    fs_err::write(path, body)?;
    Ok(())
}

pub fn load_all_file_records(
    root: &DataRoot,
    project_id: &str,
) -> Result<Vec<FileRecord>, StoreError> {
    let dir = files_dir(root, project_id)?;
    let mut out = Vec::new();
    if !dir.exists() {
        return Ok(out);
    }
    for entry in WalkDir::new(&dir).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }
        let p: &Path = entry.path();
        if p.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let body = fs_err::read_to_string(p)?;
        if let Ok(rec) = serde_json::from_str::<FileRecord>(&body) {
            out.push(rec);
        } else {
            tracing::warn!("skipping malformed file record: {}", p.display());
        }
    }
    Ok(out)
}

/// Recursively delete `dir` if it exists. Used by `init-project`.
pub fn purge_dir(dir: &PathBuf) -> Result<(), StoreError> {
    if dir.exists() {
        fs_err::remove_dir_all(dir)?;
    }
    Ok(())
}
