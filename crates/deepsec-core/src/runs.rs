use crate::ids::now_iso;
use crate::paths::{DataRoot, run_meta_path, runs_dir};
use crate::store::StoreError;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RunType {
    Scan,
    Process,
    Revalidate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RunPhase {
    Running,
    Done,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScannerMode {
    Full,
    Files,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InvocationMode {
    Scan,
    Direct,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScannerConfig {
    #[serde(rename = "matcherSlugs", default)]
    pub matcher_slugs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<ScannerMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(rename = "fileCount", skip_serializing_if = "Option::is_none")]
    pub file_count: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessorConfig {
    #[serde(rename = "agentType")]
    pub agent_type: String,
    pub model: String,
    #[serde(rename = "modelConfig", default)]
    pub model_config: IndexMap<String, serde_json::Value>,
    #[serde(rename = "invocationMode", skip_serializing_if = "Option::is_none")]
    pub invocation_mode: Option<InvocationMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RunStats {
    #[serde(rename = "filesScanned", skip_serializing_if = "Option::is_none")]
    pub files_scanned: Option<usize>,
    #[serde(rename = "candidatesFound", skip_serializing_if = "Option::is_none")]
    pub candidates_found: Option<usize>,
    #[serde(rename = "filesProcessed", skip_serializing_if = "Option::is_none")]
    pub files_processed: Option<usize>,
    #[serde(rename = "findingsCount", skip_serializing_if = "Option::is_none")]
    pub findings_count: Option<usize>,
    #[serde(rename = "totalCostUsd", skip_serializing_if = "Option::is_none")]
    pub total_cost_usd: Option<f64>,
    #[serde(rename = "totalInputTokens", skip_serializing_if = "Option::is_none")]
    pub total_input_tokens: Option<u64>,
    #[serde(rename = "totalOutputTokens", skip_serializing_if = "Option::is_none")]
    pub total_output_tokens: Option<u64>,
    #[serde(rename = "totalDurationMs", skip_serializing_if = "Option::is_none")]
    pub total_duration_ms: Option<u64>,
    #[serde(rename = "findingsRevalidated", skip_serializing_if = "Option::is_none")]
    pub findings_revalidated: Option<usize>,
    #[serde(rename = "truePositives", skip_serializing_if = "Option::is_none")]
    pub true_positives: Option<usize>,
    #[serde(rename = "falsePositives", skip_serializing_if = "Option::is_none")]
    pub false_positives: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fixed: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uncertain: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunMeta {
    #[serde(rename = "runId")]
    pub run_id: String,
    #[serde(rename = "projectId")]
    pub project_id: String,
    #[serde(rename = "rootPath")]
    pub root_path: String,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "completedAt", skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<String>,
    #[serde(rename = "type")]
    pub run_type: RunType,
    pub phase: RunPhase,
    #[serde(rename = "scannerConfig", skip_serializing_if = "Option::is_none")]
    pub scanner_config: Option<ScannerConfig>,
    #[serde(rename = "processorConfig", skip_serializing_if = "Option::is_none")]
    pub processor_config: Option<ProcessorConfig>,
    #[serde(default)]
    pub stats: RunStats,
}

pub fn create_run_meta(
    project_id: &str,
    run_id: &str,
    root_path: &str,
    run_type: RunType,
) -> RunMeta {
    RunMeta {
        run_id: run_id.into(),
        project_id: project_id.into(),
        root_path: root_path.into(),
        created_at: now_iso(),
        completed_at: None,
        run_type,
        phase: RunPhase::Running,
        scanner_config: None,
        processor_config: None,
        stats: RunStats::default(),
    }
}

pub fn write_run_meta(root: &DataRoot, meta: &RunMeta) -> Result<(), StoreError> {
    let path = run_meta_path(root, &meta.project_id, &meta.run_id)?;
    if let Some(parent) = path.parent() {
        fs_err::create_dir_all(parent)?;
    }
    let body = serde_json::to_string_pretty(meta)?;
    fs_err::write(path, body)?;
    Ok(())
}

pub fn read_run_meta(
    root: &DataRoot,
    project_id: &str,
    run_id: &str,
) -> Result<Option<RunMeta>, StoreError> {
    let path = run_meta_path(root, project_id, run_id)?;
    match fs_err::read_to_string(&path) {
        Ok(s) => Ok(Some(serde_json::from_str(&s)?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

pub fn complete_run(
    root: &DataRoot,
    project_id: &str,
    run_id: &str,
    phase: RunPhase,
) -> Result<Option<RunMeta>, StoreError> {
    let Some(mut meta) = read_run_meta(root, project_id, run_id)? else {
        return Ok(None);
    };
    meta.phase = phase;
    meta.completed_at = Some(now_iso());
    write_run_meta(root, &meta)?;
    Ok(Some(meta))
}

pub fn list_runs(root: &DataRoot, project_id: &str) -> Result<Vec<RunMeta>, StoreError> {
    let dir = runs_dir(root, project_id)?;
    let mut out = Vec::new();
    let read = match fs_err::read_dir(&dir) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e.into()),
    };
    for entry in read {
        let entry = entry?;
        let p = entry.path();
        if p.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let body = fs_err::read_to_string(&p)?;
        if let Ok(meta) = serde_json::from_str::<RunMeta>(&body) {
            out.push(meta);
        }
    }
    // Newest first. Sort by `run_id` (a "YYYYMMDDHHMMSS-XXXX" timestamp +
    // nonce) so ordering is stable across runs created in the same
    // millisecond and intuitively correct even if a meta was backdated.
    out.sort_by(|a, b| b.run_id.cmp(&a.run_id));
    Ok(out)
}
