use crate::agents::{AgentBackend, RevalidateInput, RevalidateInputFinding};
use crate::errors::ProcessorError;
use deepsec_core::ids::{generate_run_id, now_iso};
use deepsec_core::store::{load_all_file_records, write_file_record};
use deepsec_core::{
    DataRoot, InvocationMode, ProcessorConfig, Revalidation, RevalidationVerdict, RunPhase,
    RunType, Severity, complete_run, create_run_meta, write_run_meta,
};
use indexmap::IndexMap;
use std::path::PathBuf;

pub struct RevalidateOptions {
    pub project_id: String,
    pub project_root: PathBuf,
    pub data_root: DataRoot,
    pub backend: std::sync::Arc<dyn AgentBackend>,
    pub filter_prefix: Option<String>,
    pub force: bool,
}

#[derive(Debug, Default, Clone)]
pub struct RevalidateOutcome {
    pub run_id: String,
    pub revalidated: usize,
    pub true_positives: usize,
    pub false_positives: usize,
    pub fixed: usize,
    pub uncertain: usize,
}

pub async fn run_revalidate(opts: RevalidateOptions) -> Result<RevalidateOutcome, ProcessorError> {
    let run_id = generate_run_id();
    let mut meta = create_run_meta(
        &opts.project_id,
        &run_id,
        opts.project_root.to_string_lossy().as_ref(),
        RunType::Revalidate,
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

    let mut outcome = RevalidateOutcome {
        run_id: run_id.clone(),
        ..Default::default()
    };

    for mut rec in records {
        if let Some(prefix) = &opts.filter_prefix {
            if !rec.file_path.starts_with(prefix) {
                continue;
            }
        }
        let needs: Vec<(usize, &deepsec_core::Finding)> = rec
            .findings
            .iter()
            .enumerate()
            .filter(|(_, f)| opts.force || f.revalidation.is_none())
            .collect();
        if needs.is_empty() {
            continue;
        }
        let inputs: Vec<RevalidateInputFinding> = needs
            .iter()
            .map(|(i, f)| RevalidateInputFinding {
                index: *i,
                severity: f.severity,
                vuln_slug: f.vuln_slug.clone(),
                title: f.title.clone(),
                description: f.description.clone(),
                line_numbers: f.line_numbers.clone(),
            })
            .collect();
        let content = fs_err::read_to_string(opts.project_root.join(&rec.file_path))
            .unwrap_or_default();
        let input = RevalidateInput {
            project_root: opts.project_root.clone(),
            file_path: rec.file_path.clone(),
            file_content: content,
            findings: inputs,
        };
        match opts.backend.revalidate(&input).await {
            Ok((revs, _usage, _dur)) => {
                for r in revs {
                    let verdict = match r.verdict.as_str() {
                        "true-positive" => Some(RevalidationVerdict::TruePositive),
                        "false-positive" => Some(RevalidationVerdict::FalsePositive),
                        "fixed" => Some(RevalidationVerdict::Fixed),
                        "uncertain" => Some(RevalidationVerdict::Uncertain),
                        "accepted-risk" => Some(RevalidationVerdict::AcceptedRisk),
                        _ => None,
                    };
                    let Some(v) = verdict else { continue };
                    if let Some(f) = rec.findings.get_mut(r.index) {
                        f.revalidation = Some(Revalidation {
                            verdict: v,
                            reasoning: r.reasoning,
                            adjusted_severity: r.adjusted_severity.map(Severity::from_),
                            revalidated_at: now_iso(),
                            run_id: run_id.clone(),
                            model: opts.backend.model().into(),
                        });
                        outcome.revalidated += 1;
                        match v {
                            RevalidationVerdict::TruePositive => outcome.true_positives += 1,
                            RevalidationVerdict::FalsePositive => outcome.false_positives += 1,
                            RevalidationVerdict::Fixed => outcome.fixed += 1,
                            RevalidationVerdict::Uncertain => outcome.uncertain += 1,
                            _ => {}
                        }
                    }
                }
                write_file_record(&opts.data_root, &rec)
                    .map_err(|e| ProcessorError::Other(anyhow::Error::new(e)))?;
            }
            Err(ProcessorError::Quota(q)) => {
                tracing::warn!("quota exhausted: {} {}", q.backend, q.detail);
                break;
            }
            Err(e) => {
                tracing::error!("revalidate failed for {}: {e}", rec.file_path);
            }
        }
    }

    meta.stats.findings_revalidated = Some(outcome.revalidated);
    meta.stats.true_positives = Some(outcome.true_positives);
    meta.stats.false_positives = Some(outcome.false_positives);
    meta.stats.fixed = Some(outcome.fixed);
    meta.stats.uncertain = Some(outcome.uncertain);
    write_run_meta(&opts.data_root, &meta)?;
    complete_run(&opts.data_root, &opts.project_id, &run_id, RunPhase::Done)
        .map_err(|e| ProcessorError::Other(anyhow::Error::new(e)))?;
    Ok(outcome)
}

// Trampoline so we can call `Severity::from_("HIGH")` style.
trait SevFromExt {
    fn from_(s: Severity) -> Severity;
}
impl SevFromExt for Severity {
    fn from_(s: Severity) -> Severity {
        s
    }
}
