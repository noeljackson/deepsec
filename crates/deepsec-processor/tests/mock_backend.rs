//! Shared mock backend used across the processor integration tests.

use async_trait::async_trait;
use deepsec_processor::agents::{
    AgentBackend, AgentBackendKind, InvestigateBatch, InvestigateOutput, InvestigateResult,
    ProducedFinding, RevalidateInput, RevalidatedFinding, TriageInput, TriagedFinding, Usage,
};
use deepsec_processor::errors::{ProcessorError, QuotaExhausted};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Records every call so a test can assert what was dispatched.
pub struct MockBackend {
    pub kind: AgentBackendKind,
    pub model: String,
    pub investigate_calls: AtomicUsize,
    pub revalidate_calls: AtomicUsize,
    pub triage_calls: AtomicUsize,
    pub investigate_batches: Mutex<Vec<Vec<String>>>,
    /// Behavior toggles.
    pub findings_per_file: usize,
    pub return_refusal: bool,
    pub quota_after: Option<usize>,
    pub delay_ms: u64,
}

impl MockBackend {
    pub fn new() -> Self {
        Self {
            kind: AgentBackendKind::Anthropic,
            model: "mock-model".into(),
            investigate_calls: AtomicUsize::new(0),
            revalidate_calls: AtomicUsize::new(0),
            triage_calls: AtomicUsize::new(0),
            investigate_batches: Mutex::new(Vec::new()),
            findings_per_file: 1,
            return_refusal: false,
            quota_after: None,
            delay_ms: 0,
        }
    }
}

#[async_trait]
impl AgentBackend for MockBackend {
    fn kind(&self) -> AgentBackendKind {
        self.kind
    }
    fn model(&self) -> &str {
        &self.model
    }

    async fn investigate(
        &self,
        batch: &InvestigateBatch,
    ) -> Result<InvestigateOutput, ProcessorError> {
        let n = self.investigate_calls.fetch_add(1, Ordering::SeqCst);
        self.investigate_batches
            .lock()
            .unwrap()
            .push(batch.files.iter().map(|f| f.path.clone()).collect());

        if self.delay_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(self.delay_ms)).await;
        }

        if let Some(limit) = self.quota_after {
            if n >= limit {
                return Err(ProcessorError::Quota(QuotaExhausted {
                    backend: "mock".into(),
                    detail: "test-quota".into(),
                }));
            }
        }

        if self.return_refusal {
            return Err(ProcessorError::Backend("refusal: test refusal".into()));
        }

        let results: Vec<_> = batch
            .files
            .iter()
            .map(|f| InvestigateResult {
                file_path: f.path.clone(),
                findings: (0..self.findings_per_file)
                    .map(|i| ProducedFinding {
                        severity: deepsec_core::Severity::High,
                        vuln_slug: "mock-slug".into(),
                        title: format!("Mock finding {i} for {}", f.path),
                        description: "mock description".into(),
                        line_numbers: vec![1],
                        recommendation: "mock fix".into(),
                        confidence: deepsec_core::Confidence::High,
                    })
                    .collect(),
            })
            .collect();

        Ok(InvestigateOutput {
            results,
            usage: Usage {
                input_tokens: 100,
                output_tokens: 50,
                cache_read_input_tokens: 0,
                cache_creation_input_tokens: 0,
            },
            duration_ms: self.delay_ms,
            num_turns: 1,
            cost_usd: 0.01,
        })
    }

    async fn revalidate(
        &self,
        input: &RevalidateInput,
    ) -> Result<(Vec<RevalidatedFinding>, Usage, u64), ProcessorError> {
        self.revalidate_calls.fetch_add(1, Ordering::SeqCst);
        let out: Vec<_> = input
            .findings
            .iter()
            .map(|f| RevalidatedFinding {
                index: f.index,
                verdict: "true-positive".into(),
                reasoning: "still present in current code".into(),
                adjusted_severity: None,
            })
            .collect();
        Ok((out, Usage::default(), 1))
    }

    async fn triage(
        &self,
        _input: &TriageInput,
    ) -> Result<(TriagedFinding, Usage, u64), ProcessorError> {
        self.triage_calls.fetch_add(1, Ordering::SeqCst);
        Ok((
            TriagedFinding {
                priority: "P1".into(),
                exploitability: "moderate".into(),
                impact: "high".into(),
                reasoning: "mock triage".into(),
            },
            Usage::default(),
            1,
        ))
    }
}
