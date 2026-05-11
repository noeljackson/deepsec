use crate::agents::{AgentBackend, RevalidateInputFinding, TriageInput};
use crate::errors::ProcessorError;
use deepsec_core::ids::{generate_run_id, now_iso};
use deepsec_core::store::{load_all_file_records, write_file_record};
use deepsec_core::{
    DataRoot, Exploitability, Impact, InvocationMode, ProcessorConfig, RunPhase, RunType,
    Triage, TriagePriority, complete_run, create_run_meta, write_run_meta,
};
use indexmap::IndexMap;
use std::path::PathBuf;

pub struct TriageOptions {
    pub project_id: String,
    pub project_root: PathBuf,
    pub data_root: DataRoot,
    pub backend: std::sync::Arc<dyn AgentBackend>,
    pub filter_prefix: Option<String>,
    pub force: bool,
}

#[derive(Debug, Default, Clone)]
pub struct TriageOutcome {
    pub run_id: String,
    pub triaged: usize,
}

pub async fn run_triage(opts: TriageOptions) -> Result<TriageOutcome, ProcessorError> {
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
    let mut outcome = TriageOutcome {
        run_id: run_id.clone(),
        ..Default::default()
    };

    for mut rec in records {
        if let Some(prefix) = &opts.filter_prefix {
            if !rec.file_path.starts_with(prefix) {
                continue;
            }
        }
        let mut changed = false;
        let len = rec.findings.len();
        for i in 0..len {
            if !opts.force && rec.findings[i].triage.is_some() {
                continue;
            }
            let f = &rec.findings[i];
            let input = TriageInput {
                file_path: rec.file_path.clone(),
                finding: RevalidateInputFinding {
                    index: i,
                    severity: f.severity,
                    vuln_slug: f.vuln_slug.clone(),
                    title: f.title.clone(),
                    description: f.description.clone(),
                    line_numbers: f.line_numbers.clone(),
                },
            };
            match opts.backend.triage(&input).await {
                Ok((t, _u, _d)) => {
                    let priority = match t.priority.as_str() {
                        "P0" => TriagePriority::P0,
                        "P1" => TriagePriority::P1,
                        "P2" => TriagePriority::P2,
                        _ => TriagePriority::Skip,
                    };
                    let exploit = match t.exploitability.as_str() {
                        "trivial" => Exploitability::Trivial,
                        "moderate" => Exploitability::Moderate,
                        _ => Exploitability::Difficult,
                    };
                    let impact = match t.impact.as_str() {
                        "critical" => Impact::Critical,
                        "high" => Impact::High,
                        "medium" => Impact::Medium,
                        _ => Impact::Low,
                    };
                    rec.findings[i].triage = Some(Triage {
                        priority,
                        exploitability: exploit,
                        impact,
                        reasoning: t.reasoning,
                        triaged_at: now_iso(),
                        model: opts.backend.model().into(),
                    });
                    outcome.triaged += 1;
                    changed = true;
                }
                Err(ProcessorError::Quota(q)) => {
                    tracing::warn!("triage quota exhausted: {} {}", q.backend, q.detail);
                    break;
                }
                Err(e) => {
                    tracing::error!("triage failed for {}: {e}", rec.file_path);
                }
            }
        }
        if changed {
            write_file_record(&opts.data_root, &rec)
                .map_err(|e| ProcessorError::Other(anyhow::Error::new(e)))?;
        }
    }

    write_run_meta(&opts.data_root, &meta)?;
    complete_run(&opts.data_root, &opts.project_id, &run_id, RunPhase::Done)
        .map_err(|e| ProcessorError::Other(anyhow::Error::new(e)))?;
    Ok(outcome)
}
