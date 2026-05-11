use crate::agents::{
    AgentBackend, InvestigateBatch, InvestigateFile, ProducedFinding,
};
use crate::batch::batch_records;
use crate::errors::ProcessorError;
use deepsec_core::ids::{generate_run_id, now_iso};
use deepsec_core::store::{load_all_file_records, read_file_record, write_file_record};
use deepsec_core::{
    AnalysisEntry, AnalysisPhase, DataRoot, FileRecord, FileStatus, Finding, InvocationMode,
    ProcessorConfig, RunPhase, RunType, Usage as CoreUsage, complete_run, create_run_meta,
    write_run_meta,
};
use deepsec_scanner::DetectedTech;
use indexmap::IndexMap;
use std::collections::HashSet;
use std::path::PathBuf;

pub struct ProcessOptions {
    pub project_id: String,
    pub project_root: PathBuf,
    pub data_root: DataRoot,
    pub backend: Box<dyn AgentBackend>,
    pub batch_size: usize,
    pub limit: Option<usize>,
    pub filter_prefix: Option<String>,
    pub only_slugs: Vec<String>,
    pub skip_slugs: Vec<String>,
    pub project_info: Option<String>,
    pub prompt_append: Option<String>,
    pub detected: Option<DetectedTech>,
}

#[derive(Debug, Clone, Default)]
pub struct ProcessOutcome {
    pub run_id: String,
    pub batches_run: usize,
    pub analysis_count: usize,
    pub finding_count: usize,
    pub error_batch_count: usize,
    pub quota_exhausted: bool,
}

pub async fn run_process(opts: ProcessOptions) -> Result<ProcessOutcome, ProcessorError> {
    let run_id = generate_run_id();
    let mut meta = create_run_meta(
        &opts.project_id,
        &run_id,
        opts.project_root.to_string_lossy().as_ref(),
        RunType::Process,
    );
    meta.processor_config = Some(ProcessorConfig {
        agent_type: opts.backend.kind().as_str().into(),
        model: opts.backend.model().into(),
        model_config: IndexMap::new(),
        invocation_mode: Some(InvocationMode::Scan),
        source: None,
    });
    write_run_meta(&opts.data_root, &meta)?;

    let records = load_all_file_records(&opts.data_root, &opts.project_id)
        .map_err(|e| ProcessorError::Other(anyhow::Error::new(e)))?;

    let only: HashSet<&str> = opts.only_slugs.iter().map(String::as_str).collect();
    let skip: HashSet<&str> = opts.skip_slugs.iter().map(String::as_str).collect();

    let mut work: Vec<FileRecord> = records
        .into_iter()
        .filter(|r| !r.candidates.is_empty())
        .filter(|r| matches!(r.status, FileStatus::Pending | FileStatus::Error))
        .filter(|r| {
            opts.filter_prefix
                .as_deref()
                .map(|p| r.file_path.starts_with(p))
                .unwrap_or(true)
        })
        .filter(|r| {
            if !only.is_empty() {
                r.candidates.iter().any(|c| only.contains(c.vuln_slug.as_str()))
            } else {
                true
            }
        })
        .filter(|r| {
            if skip.is_empty() {
                return true;
            }
            r.candidates.iter().any(|c| !skip.contains(c.vuln_slug.as_str()))
        })
        .collect();

    // priority: precise candidates first, then by count
    work.sort_by_key(|r| (r.candidates.len() == 0, r.file_path.clone()));

    if let Some(lim) = opts.limit {
        work.truncate(lim);
    }

    let tech_tags = opts
        .detected
        .as_ref()
        .map(|d| d.tags.clone())
        .unwrap_or_default();

    let mut outcome = ProcessOutcome {
        run_id: run_id.clone(),
        ..Default::default()
    };

    let batches = batch_records(&work, opts.batch_size.max(1));
    outcome.batches_run = batches.len();

    let mut total_findings = 0usize;
    let mut total_input = 0u64;
    let mut total_output = 0u64;
    let mut total_cost = 0.0f64;
    let mut total_duration = 0u64;

    for batch in batches {
        let invoke_batch = build_invoke_batch(
            &opts.project_root,
            &batch,
            &tech_tags,
            opts.project_info.as_deref(),
            opts.prompt_append.as_deref(),
        );

        // mark locked
        for r in &batch {
            if let Some(mut rec) = read_file_record(&opts.data_root, &opts.project_id, &r.file_path)
                .map_err(|e| ProcessorError::Other(anyhow::Error::new(e)))?
            {
                rec.status = FileStatus::Processing;
                rec.locked_by_run_id = Some(run_id.clone());
                rec.locked_at = Some(now_iso());
                write_file_record(&opts.data_root, &rec)
                    .map_err(|e| ProcessorError::Other(anyhow::Error::new(e)))?;
            }
        }

        let result = opts.backend.investigate(&invoke_batch).await;
        match result {
            Ok(out) => {
                total_input += out.usage.input_tokens;
                total_output += out.usage.output_tokens;
                total_cost += out.cost_usd;
                total_duration += out.duration_ms;

                let per_file_cost = if !batch.is_empty() {
                    out.cost_usd / batch.len() as f64
                } else {
                    0.0
                };
                let per_file_usage = CoreUsage {
                    input_tokens: out.usage.input_tokens / batch.len().max(1) as u64,
                    output_tokens: out.usage.output_tokens / batch.len().max(1) as u64,
                    cache_read_input_tokens: out.usage.cache_read_input_tokens
                        / batch.len().max(1) as u64,
                    cache_creation_input_tokens: out.usage.cache_creation_input_tokens
                        / batch.len().max(1) as u64,
                };
                let per_file_duration = out.duration_ms / batch.len().max(1) as u64;

                let results_by_file: std::collections::HashMap<String, Vec<ProducedFinding>> =
                    out.results
                        .into_iter()
                        .map(|r| (r.file_path, r.findings))
                        .collect();

                for r in &batch {
                    let Some(mut rec) =
                        read_file_record(&opts.data_root, &opts.project_id, &r.file_path)
                            .map_err(|e| ProcessorError::Other(anyhow::Error::new(e)))?
                    else {
                        continue;
                    };
                    let findings = results_by_file.get(&r.file_path).cloned().unwrap_or_default();

                    apply_findings(&mut rec, &run_id, findings.clone());

                    let entry = AnalysisEntry {
                        run_id: run_id.clone(),
                        investigated_at: now_iso(),
                        duration_ms: per_file_duration,
                        duration_api_ms: None,
                        agent_type: opts.backend.kind().as_str().into(),
                        model: opts.backend.model().into(),
                        model_config: IndexMap::new(),
                        agent_session_id: None,
                        finding_count: findings.len(),
                        num_turns: Some(out.num_turns),
                        phase: Some(AnalysisPhase::Process),
                        cost_usd: Some(per_file_cost),
                        usage: Some(per_file_usage.clone()),
                        refusal: None,
                        codex_stderr: None,
                        reinvestigate_marker: None,
                    };
                    rec.analysis_history.push(entry);
                    rec.status = FileStatus::Analyzed;
                    rec.locked_by_run_id = None;
                    rec.locked_at = None;
                    total_findings += findings.len();
                    write_file_record(&opts.data_root, &rec)
                        .map_err(|e| ProcessorError::Other(anyhow::Error::new(e)))?;
                    outcome.analysis_count += 1;
                }
            }
            Err(ProcessorError::Quota(q)) => {
                tracing::warn!("quota exhausted on {}: {}", q.backend, q.detail);
                outcome.quota_exhausted = true;
                outcome.error_batch_count += 1;
                for r in &batch {
                    if let Some(mut rec) =
                        read_file_record(&opts.data_root, &opts.project_id, &r.file_path)
                            .map_err(|e| ProcessorError::Other(anyhow::Error::new(e)))?
                    {
                        rec.status = FileStatus::Pending;
                        rec.locked_by_run_id = None;
                        rec.locked_at = None;
                        write_file_record(&opts.data_root, &rec)
                            .map_err(|e| ProcessorError::Other(anyhow::Error::new(e)))?;
                    }
                }
                break;
            }
            Err(e) => {
                tracing::error!("batch failed: {e}");
                outcome.error_batch_count += 1;
                for r in &batch {
                    if let Some(mut rec) =
                        read_file_record(&opts.data_root, &opts.project_id, &r.file_path)
                            .map_err(|e| ProcessorError::Other(anyhow::Error::new(e)))?
                    {
                        rec.status = FileStatus::Error;
                        rec.locked_by_run_id = None;
                        rec.locked_at = None;
                        write_file_record(&opts.data_root, &rec)
                            .map_err(|e| ProcessorError::Other(anyhow::Error::new(e)))?;
                    }
                }
            }
        }
    }

    outcome.finding_count = total_findings;
    meta.stats.files_processed = Some(outcome.analysis_count);
    meta.stats.findings_count = Some(total_findings);
    meta.stats.total_input_tokens = Some(total_input);
    meta.stats.total_output_tokens = Some(total_output);
    meta.stats.total_cost_usd = Some(total_cost);
    meta.stats.total_duration_ms = Some(total_duration);
    write_run_meta(&opts.data_root, &meta)?;
    let final_phase = if outcome.error_batch_count > 0 && outcome.analysis_count == 0 {
        RunPhase::Error
    } else {
        RunPhase::Done
    };
    complete_run(&opts.data_root, &opts.project_id, &run_id, final_phase)
        .map_err(|e| ProcessorError::Other(anyhow::Error::new(e)))?;
    Ok(outcome)
}

fn build_invoke_batch(
    root: &PathBuf,
    batch: &[&FileRecord],
    tech_tags: &[String],
    project_info: Option<&str>,
    prompt_append: Option<&str>,
) -> InvestigateBatch {
    let mut files = Vec::with_capacity(batch.len());
    let mut slug_set: indexmap::IndexSet<String> = indexmap::IndexSet::new();
    for r in batch {
        let content = fs_err::read_to_string(root.join(&r.file_path)).unwrap_or_default();
        for c in &r.candidates {
            slug_set.insert(c.vuln_slug.clone());
        }
        files.push(InvestigateFile {
            path: r.file_path.clone(),
            content,
            candidates: r.candidates.clone(),
        });
    }
    InvestigateBatch {
        project_root: root.clone(),
        files,
        project_info: project_info.map(str::to_string),
        prompt_append: prompt_append.map(str::to_string),
        tech_tags: tech_tags.to_vec(),
        slug_notes: slug_set.into_iter().map(|s| (s, String::new())).collect(),
    }
}

fn apply_findings(rec: &mut FileRecord, run_id: &str, findings: Vec<ProducedFinding>) {
    let mut existing: HashSet<String> = rec
        .findings
        .iter()
        .map(|f| format!("{}|{}", f.vuln_slug, f.title))
        .collect();
    for f in findings {
        let key = format!("{}|{}", f.vuln_slug, f.title);
        if !existing.insert(key) {
            continue;
        }
        rec.findings.push(Finding {
            severity: f.severity,
            vuln_slug: f.vuln_slug,
            title: f.title,
            description: f.description,
            line_numbers: f.line_numbers,
            recommendation: f.recommendation,
            confidence: f.confidence,
            triage: None,
            revalidation: None,
            produced_by_run_id: Some(run_id.to_string()),
        });
    }
}
