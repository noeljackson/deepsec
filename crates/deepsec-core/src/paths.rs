use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PathError {
    #[error("Invalid {label}: must be a non-empty string")]
    Empty { label: &'static str },
    #[error("Invalid {label}: \"{value}\"")]
    DotSegment { label: &'static str, value: String },
    #[error("Invalid {label}: contains null byte")]
    NullByte { label: &'static str },
    #[error("Invalid {label}: contains path separator")]
    Separator { label: &'static str },
    #[error("Invalid {label}: must not be absolute")]
    Absolute { label: &'static str },
    #[error("Invalid filePath: contains \"{segment}\" segment")]
    BadFilePathSegment { segment: String },
    #[error("Invalid filePath: contains backslash")]
    Backslash,
}

/// Reject empty, '.', '..', absolute paths, null bytes, and any path
/// separator. Used at every entry point that joins user-supplied
/// segments onto a per-project mirror so a `../`-laced
/// projectId/runId can't escape the mirror or clobber a sibling
/// project's files.
pub fn assert_safe_segment(name: &str, label: &'static str) -> Result<(), PathError> {
    if name.is_empty() {
        return Err(PathError::Empty { label });
    }
    if name == "." || name == ".." {
        return Err(PathError::DotSegment {
            label,
            value: name.into(),
        });
    }
    if name.contains('\0') {
        return Err(PathError::NullByte { label });
    }
    if name.contains('/') || name.contains('\\') {
        return Err(PathError::Separator { label });
    }
    if Path::new(name).is_absolute() {
        return Err(PathError::Absolute { label });
    }
    Ok(())
}

/// FilePath is a relative path under a project root. We allow `/`
/// between segments but reject `..` components, absolute paths,
/// null bytes, and backslashes.
pub fn assert_safe_file_path(file_path: &str) -> Result<(), PathError> {
    if file_path.is_empty() {
        return Err(PathError::Empty { label: "filePath" });
    }
    if file_path.contains('\0') {
        return Err(PathError::NullByte { label: "filePath" });
    }
    if file_path.contains('\\') {
        return Err(PathError::Backslash);
    }
    if Path::new(file_path).is_absolute() {
        return Err(PathError::Absolute { label: "filePath" });
    }
    for part in file_path.split('/') {
        if part.is_empty() || part == "." || part == ".." {
            return Err(PathError::BadFilePathSegment {
                segment: part.into(),
            });
        }
    }
    Ok(())
}

/// Root of the on-disk data mirror. Defaults to `data/` relative to
/// the working directory, overridable via `DEEPSEC_DATA_ROOT`.
#[derive(Debug, Clone)]
pub struct DataRoot(pub PathBuf);

impl DataRoot {
    pub fn from_env() -> Self {
        if let Ok(s) = std::env::var("DEEPSEC_DATA_ROOT") {
            return DataRoot(PathBuf::from(s));
        }
        DataRoot(PathBuf::from("data"))
    }

    pub fn from_path(p: impl Into<PathBuf>) -> Self {
        DataRoot(p.into())
    }

    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

pub fn data_dir(root: &DataRoot, project_id: &str) -> Result<PathBuf, PathError> {
    assert_safe_segment(project_id, "projectId")?;
    Ok(root.0.join(project_id))
}

pub fn project_config_path(root: &DataRoot, project_id: &str) -> Result<PathBuf, PathError> {
    Ok(data_dir(root, project_id)?.join("project.json"))
}

pub fn files_dir(root: &DataRoot, project_id: &str) -> Result<PathBuf, PathError> {
    Ok(data_dir(root, project_id)?.join("files"))
}

pub fn file_record_path(
    root: &DataRoot,
    project_id: &str,
    file_path: &str,
) -> Result<PathBuf, PathError> {
    assert_safe_file_path(file_path)?;
    let mut p = files_dir(root, project_id)?;
    for seg in file_path.split('/') {
        p.push(seg);
    }
    p.set_extension({
        let cur = p.extension().map(|e| e.to_string_lossy().into_owned());
        match cur {
            Some(e) => format!("{e}.json"),
            None => "json".to_string(),
        }
    });
    Ok(p)
}

pub fn runs_dir(root: &DataRoot, project_id: &str) -> Result<PathBuf, PathError> {
    Ok(data_dir(root, project_id)?.join("runs"))
}

pub fn run_meta_path(
    root: &DataRoot,
    project_id: &str,
    run_id: &str,
) -> Result<PathBuf, PathError> {
    assert_safe_segment(run_id, "runId")?;
    Ok(runs_dir(root, project_id)?.join(format!("{run_id}.json")))
}

pub fn reports_dir(root: &DataRoot, project_id: &str) -> Result<PathBuf, PathError> {
    Ok(data_dir(root, project_id)?.join("reports"))
}

fn report_name(prefix: &str, run_id: Option<&str>, ext: &str) -> Result<String, PathError> {
    if let Some(id) = run_id {
        assert_safe_segment(id, "runId")?;
        Ok(format!("{prefix}-{id}.{ext}"))
    } else {
        Ok(format!("{prefix}.{ext}"))
    }
}

pub fn report_json_path(
    root: &DataRoot,
    project_id: &str,
    run_id: Option<&str>,
) -> Result<PathBuf, PathError> {
    Ok(reports_dir(root, project_id)?.join(report_name("report", run_id, "json")?))
}

pub fn report_md_path(
    root: &DataRoot,
    project_id: &str,
    run_id: Option<&str>,
) -> Result<PathBuf, PathError> {
    Ok(reports_dir(root, project_id)?.join(report_name("report", run_id, "md")?))
}

pub fn report_csv_path(
    root: &DataRoot,
    project_id: &str,
    run_id: Option<&str>,
) -> Result<PathBuf, PathError> {
    Ok(reports_dir(root, project_id)?.join(report_name("report", run_id, "csv")?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_path_traversal() {
        assert!(assert_safe_segment("..", "projectId").is_err());
        assert!(assert_safe_segment("a/b", "projectId").is_err());
        assert!(assert_safe_segment("", "projectId").is_err());
        assert!(assert_safe_segment("ok", "projectId").is_ok());
    }

    #[test]
    fn file_path_validation() {
        assert!(assert_safe_file_path("src/foo.ts").is_ok());
        assert!(assert_safe_file_path("../etc/passwd").is_err());
        assert!(assert_safe_file_path("/abs").is_err());
        assert!(assert_safe_file_path("a\\b").is_err());
    }

    #[test]
    fn file_record_path_appends_json() {
        let r = DataRoot::from_path("data");
        let p = file_record_path(&r, "p", "src/x.ts").unwrap();
        assert!(p.ends_with("data/p/files/src/x.ts.json"));
    }
}
