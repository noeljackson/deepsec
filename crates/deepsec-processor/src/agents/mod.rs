pub mod anthropic;
pub mod openai;
mod shared;

use crate::errors::ProcessorError;
use async_trait::async_trait;
use deepsec_core::{CandidateMatch, Confidence, Severity};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentBackendKind {
    Anthropic,
    OpenAi,
}

impl AgentBackendKind {
    pub fn as_str(self) -> &'static str {
        match self {
            AgentBackendKind::Anthropic => "anthropic",
            AgentBackendKind::OpenAi => "openai",
        }
    }
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "anthropic" | "claude" | "claude-agent-sdk" => Some(Self::Anthropic),
            "openai" | "codex" | "codex-sdk" | "gpt" => Some(Self::OpenAi),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BackendChoice {
    pub kind: AgentBackendKind,
    pub model: String,
    pub api_key: String,
    pub base_url: Option<String>,
}

#[derive(Debug, Clone)]
pub struct InvestigateBatch {
    pub project_root: std::path::PathBuf,
    pub files: Vec<InvestigateFile>,
    pub project_info: Option<String>,
    pub prompt_append: Option<String>,
    pub tech_tags: Vec<String>,
    pub slug_notes: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
pub struct InvestigateFile {
    pub path: String,
    pub content: String,
    pub candidates: Vec<CandidateMatch>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Usage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_input_tokens: u64,
    pub cache_creation_input_tokens: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProducedFinding {
    pub severity: Severity,
    #[serde(rename = "vulnSlug", alias = "vuln_slug")]
    pub vuln_slug: String,
    pub title: String,
    pub description: String,
    #[serde(rename = "lineNumbers", alias = "line_numbers")]
    pub line_numbers: Vec<usize>,
    pub recommendation: String,
    pub confidence: Confidence,
}

#[derive(Debug, Clone)]
pub struct InvestigateResult {
    pub file_path: String,
    pub findings: Vec<ProducedFinding>,
}

#[derive(Debug, Clone)]
pub struct InvestigateOutput {
    pub results: Vec<InvestigateResult>,
    pub usage: Usage,
    pub duration_ms: u64,
    pub num_turns: u32,
    pub cost_usd: f64,
}

#[derive(Debug, Clone)]
pub struct RevalidateInput {
    pub project_root: std::path::PathBuf,
    pub file_path: String,
    pub file_content: String,
    pub findings: Vec<RevalidateInputFinding>,
}

#[derive(Debug, Clone)]
pub struct RevalidateInputFinding {
    pub index: usize,
    pub severity: Severity,
    pub vuln_slug: String,
    pub title: String,
    pub description: String,
    pub line_numbers: Vec<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevalidatedFinding {
    pub index: usize,
    pub verdict: String,
    pub reasoning: String,
    pub adjusted_severity: Option<Severity>,
}

#[derive(Debug, Clone)]
pub struct TriageInput {
    pub file_path: String,
    pub finding: RevalidateInputFinding,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriagedFinding {
    pub priority: String,
    pub exploitability: String,
    pub impact: String,
    pub reasoning: String,
}

#[async_trait]
pub trait AgentBackend: Send + Sync {
    fn kind(&self) -> AgentBackendKind;
    fn model(&self) -> &str;

    async fn investigate(
        &self,
        batch: &InvestigateBatch,
    ) -> Result<InvestigateOutput, ProcessorError>;

    async fn revalidate(
        &self,
        input: &RevalidateInput,
    ) -> Result<(Vec<RevalidatedFinding>, Usage, u64), ProcessorError>;

    async fn triage(
        &self,
        input: &TriageInput,
    ) -> Result<(TriagedFinding, Usage, u64), ProcessorError>;
}

pub fn make_backend(choice: BackendChoice) -> Box<dyn AgentBackend> {
    match choice.kind {
        AgentBackendKind::Anthropic => Box::new(anthropic::AnthropicBackend::new(
            choice.api_key,
            choice.model,
            choice.base_url,
        )),
        AgentBackendKind::OpenAi => Box::new(openai::OpenAiBackend::new(
            choice.api_key,
            choice.model,
            choice.base_url,
        )),
    }
}
