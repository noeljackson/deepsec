use crate::agents::{
    AgentBackend, InvestigateBatch, InvestigateFile, InvestigateOutput, ProducedFinding,
};
use crate::batch::batch_records;
use crate::errors::ProcessorError;
use deepsec_core::ids::{generate_run_id, now_iso};
use deepsec_core::store::{load_all_file_records, read_file_record, write_file_record};
use deepsec_core::{
    AnalysisEntry, AnalysisPhase, DataRoot, FileRecord, FileStatus, Finding, InvocationMode,
    ProcessorConfig, RefusalReport, RunPhase, RunType, Usage as CoreUsage, complete_run,
    create_run_meta, write_run_meta,
};
use deepsec_scanner::DetectedTech;
use futures::stream::{FuturesUnordered, StreamExt};
use indexmap::IndexMap;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::Semaphore;

pub struct ProcessOptions {
    pub project_id: String,
    pub project_root: PathBuf,
    pub data_root: DataRoot,
    pub backend: Arc<dyn AgentBackend>,
    pub batch_size: usize,
    /// Max concurrent in-flight batches. Defaults to 4.
    pub concurrency: usize,
    pub limit: Option<usize>,
    pub filter_prefix: Option<String>,
    pub only_slugs: Vec<String>,
    pub skip_slugs: Vec<String>,
    pub project_info: Option<String>,
    pub prompt_append: Option<String>,
    pub detected: Option<DetectedTech>,
    /// Direct mode: process exactly these file paths, regardless of
    /// their current `status` (overrides the pending/error filter).
    /// Used by `process --diff` and `process --files`.
    pub direct_files: Option<Vec<String>>,
    /// Direct mode source label, e.g. `git-diff:origin/main`. Recorded
    /// in `RunMeta.processorConfig.source`.
    pub direct_source: Option<String>,
    /// Wave marker. When set, files that already have an analysis
    /// entry carrying this marker (and the same agent type) are skipped.
    pub reinvestigate_marker: Option<u32>,
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

#[derive(Debug)]
enum BatchResult {
    Ok {
        paths: Vec<String>,
        output: InvestigateOutput,
    },
    Quota {
        paths: Vec<String>,
        detail: String,
    },
    Refusal {
        paths: Vec<String>,
        reason: String,
    },
    Cancelled {
        paths: Vec<String>,
    },
    Error {
        paths: Vec<String>,
        error: String,
    },
}

pub async fn run_process(opts: ProcessOptions) -> Result<ProcessOutcome, ProcessorError> {
    let run_id = generate_run_id();
    let mut meta = create_run_meta(
        &opts.project_id,
        &run_id,
        opts.project_root.to_string_lossy().as_ref(),
        RunType::Process,
    );
    let direct_mode = opts.direct_files.is_some();
    meta.processor_config = Some(ProcessorConfig {
        agent_type: opts.backend.kind().as_str().into(),
        model: opts.backend.model().into(),
        model_config: IndexMap::new(),
        invocation_mode: Some(if direct_mode {
            InvocationMode::Direct
        } else {
            InvocationMode::Scan
        }),
        source: opts.direct_source.clone(),
    });
    write_run_meta(&opts.data_root, &meta)?;

    let records = load_all_file_records(&opts.data_root, &opts.project_id)?;

    let only: HashSet<&str> = opts.only_slugs.iter().map(String::as_str).collect();
    let skip: HashSet<&str> = opts.skip_slugs.iter().map(String::as_str).collect();
    let direct_set: Option<HashSet<&str>> = opts
        .direct_files
        .as_ref()
        .map(|v| v.iter().map(String::as_str).collect());

    let mut work: Vec<FileRecord> = records
        .into_iter()
        .filter(|r| {
            if let Some(set) = &direct_set {
                return set.contains(r.file_path.as_str());
            }
            !r.candidates.is_empty()
                && matches!(r.status, FileStatus::Pending | FileStatus::Error)
        })
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
        .filter(|r| {
            // reinvestigate wave: skip files already analyzed at this wave
            let Some(wave) = opts.reinvestigate_marker else {
                return true;
            };
            !r.analysis_history.iter().any(|a| {
                a.reinvestigate_marker == Some(wave)
                    && a.agent_type == opts.backend.kind().as_str()
                    && a.phase != Some(deepsec_core::AnalysisPhase::Revalidate)
            })
        })
        .collect();

    work.sort_by_key(|r| (r.candidates.is_empty(), r.file_path.clone()));
    if let Some(lim) = opts.limit {
        work.truncate(lim);
    }

    let tech_tags = opts
        .detected
        .as_ref()
        .map(|d| d.tags.clone())
        .unwrap_or_default();

    let batches = batch_records(&work, opts.batch_size.max(1));
    let mut outcome = ProcessOutcome {
        run_id: run_id.clone(),
        batches_run: batches.len(),
        ..Default::default()
    };

    // Lock all batched records up front so a parallel run won't pick them up.
    let now = now_iso();
    for batch in &batches {
        for r in batch {
            if let Some(mut rec) = read_file_record(&opts.data_root, &opts.project_id, &r.file_path)?
            {
                rec.status = FileStatus::Processing;
                rec.locked_by_run_id = Some(run_id.clone());
                rec.locked_at = Some(now.clone());
                write_file_record(&opts.data_root, &rec)?;
            }
        }
    }

    let backend = opts.backend.clone();
    let semaphore = Arc::new(Semaphore::new(opts.concurrency.max(1)));
    let cancelled = Arc::new(AtomicBool::new(false));

    let mut futs: FuturesUnordered<_> = FuturesUnordered::new();
    for batch in batches {
        let invoke = build_invoke_batch(
            &opts.project_root,
            &batch,
            &tech_tags,
            opts.project_info.as_deref(),
            opts.prompt_append.as_deref(),
        );
        let paths: Vec<String> = batch.iter().map(|r| r.file_path.clone()).collect();
        let backend = backend.clone();
        let sem = semaphore.clone();
        let cancel = cancelled.clone();
        futs.push(async move {
            if cancel.load(Ordering::Acquire) {
                return BatchResult::Cancelled { paths };
            }
            let _permit = sem.acquire().await.unwrap();
            if cancel.load(Ordering::Acquire) {
                return BatchResult::Cancelled { paths };
            }
            match backend.investigate(&invoke).await {
                Ok(out) => BatchResult::Ok { paths, output: out },
                Err(ProcessorError::Quota(q)) => {
                    cancel.store(true, Ordering::Release);
                    BatchResult::Quota {
                        paths,
                        detail: q.detail,
                    }
                }
                Err(e) => {
                    let msg = format!("{e}");
                    if msg.to_lowercase().contains("refus") {
                        BatchResult::Refusal { paths, reason: msg }
                    } else {
                        BatchResult::Error { paths, error: msg }
                    }
                }
            }
        });
    }

    let mut total_findings = 0usize;
    let mut total_input = 0u64;
    let mut total_output = 0u64;
    let mut total_cost = 0.0f64;
    let mut total_duration = 0u64;

    while let Some(result) = futs.next().await {
        match result {
            BatchResult::Ok { paths, output } => {
                total_input += output.usage.input_tokens;
                total_output += output.usage.output_tokens;
                total_cost += output.cost_usd;
                total_duration += output.duration_ms;
                let n = paths.len().max(1) as u64;
                let per_file_cost = output.cost_usd / n as f64;
                let per_file_usage = CoreUsage {
                    input_tokens: output.usage.input_tokens / n,
                    output_tokens: output.usage.output_tokens / n,
                    cache_read_input_tokens: output.usage.cache_read_input_tokens / n,
                    cache_creation_input_tokens: output.usage.cache_creation_input_tokens / n,
                };
                let per_file_duration = output.duration_ms / n;

                let mut results_by_file: std::collections::HashMap<String, Vec<ProducedFinding>> =
                    output
                        .results
                        .into_iter()
                        .map(|r| (r.file_path, r.findings))
                        .collect();

                for path in &paths {
                    let Some(mut rec) =
                        read_file_record(&opts.data_root, &opts.project_id, path)?
                    else {
                        continue;
                    };
                    let findings = results_by_file.remove(path).unwrap_or_default();
                    apply_findings(&mut rec, &run_id, findings.clone());
                    rec.analysis_history.push(AnalysisEntry {
                        run_id: run_id.clone(),
                        investigated_at: now_iso(),
                        duration_ms: per_file_duration,
                        duration_api_ms: None,
                        agent_type: opts.backend.kind().as_str().into(),
                        model: opts.backend.model().into(),
                        model_config: IndexMap::new(),
                        agent_session_id: None,
                        finding_count: findings.len(),
                        num_turns: Some(output.num_turns),
                        phase: Some(AnalysisPhase::Process),
                        cost_usd: Some(per_file_cost),
                        usage: Some(per_file_usage.clone()),
                        refusal: None,
                        codex_stderr: None,
                        reinvestigate_marker: opts.reinvestigate_marker,
                    });
                    rec.status = FileStatus::Analyzed;
                    rec.locked_by_run_id = None;
                    rec.locked_at = None;
                    total_findings += findings.len();
                    write_file_record(&opts.data_root, &rec)?;
                    outcome.analysis_count += 1;
                }
            }
            BatchResult::Quota { paths, detail } => {
                outcome.quota_exhausted = true;
                outcome.error_batch_count += 1;
                tracing::warn!("quota exhausted: {detail}");
                release_locks(&opts.data_root, &opts.project_id, &paths, FileStatus::Pending)?;
            }
            BatchResult::Cancelled { paths } => {
                // Batches cancelled by an upstream quota signal go back
                // to pending so the user can retry.
                release_locks(&opts.data_root, &opts.project_id, &paths, FileStatus::Pending)?;
            }
            BatchResult::Refusal { paths, reason } => {
                outcome.error_batch_count += 1;
                for path in &paths {
                    if let Some(mut rec) =
                        read_file_record(&opts.data_root, &opts.project_id, path)?
                    {
                        rec.analysis_history.push(AnalysisEntry {
                            run_id: run_id.clone(),
                            investigated_at: now_iso(),
                            duration_ms: 0,
                            duration_api_ms: None,
                            agent_type: opts.backend.kind().as_str().into(),
                            model: opts.backend.model().into(),
                            model_config: IndexMap::new(),
                            agent_session_id: None,
                            finding_count: 0,
                            num_turns: None,
                            phase: Some(AnalysisPhase::Process),
                            cost_usd: None,
                            usage: None,
                            refusal: Some(RefusalReport {
                                refused: true,
                                reason: Some(reason.clone()),
                                skipped: None,
                                raw: None,
                            }),
                            codex_stderr: None,
                            reinvestigate_marker: None,
                        });
                        rec.status = FileStatus::Error;
                        rec.locked_by_run_id = None;
                        rec.locked_at = None;
                        write_file_record(&opts.data_root, &rec)?;
                    }
                }
            }
            BatchResult::Error { paths, error } => {
                outcome.error_batch_count += 1;
                tracing::error!("batch failed: {error}");
                release_locks(&opts.data_root, &opts.project_id, &paths, FileStatus::Error)?;
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
    complete_run(&opts.data_root, &opts.project_id, &run_id, final_phase)?;
    Ok(outcome)
}

fn release_locks(
    root: &DataRoot,
    project_id: &str,
    paths: &[String],
    new_status: FileStatus,
) -> Result<(), ProcessorError> {
    for path in paths {
        if let Some(mut rec) = read_file_record(root, project_id, path)? {
            rec.status = new_status;
            rec.locked_by_run_id = None;
            rec.locked_at = None;
            write_file_record(root, &rec)?;
        }
    }
    Ok(())
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
