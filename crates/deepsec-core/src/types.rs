use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    #[serde(rename = "CRITICAL")]
    Critical,
    #[serde(rename = "HIGH")]
    High,
    #[serde(rename = "MEDIUM")]
    Medium,
    #[serde(rename = "HIGH_BUG")]
    HighBug,
    #[serde(rename = "BUG")]
    Bug,
    #[serde(rename = "LOW")]
    Low,
}

impl Severity {
    pub fn rank(self) -> u8 {
        match self {
            Severity::Critical => 6,
            Severity::High => 5,
            Severity::HighBug => 4,
            Severity::Medium => 3,
            Severity::Bug => 2,
            Severity::Low => 1,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::HighBug => "HIGH_BUG",
            Severity::Medium => "MEDIUM",
            Severity::Bug => "BUG",
            Severity::Low => "LOW",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RevalidationVerdict {
    TruePositive,
    FalsePositive,
    Fixed,
    Uncertain,
    AcceptedRisk,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TriagePriority {
    P0,
    P1,
    P2,
    #[serde(rename = "skip")]
    Skip,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileStatus {
    Pending,
    Processing,
    Analyzed,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidateMatch {
    #[serde(rename = "vulnSlug")]
    pub vuln_slug: String,
    #[serde(rename = "lineNumbers")]
    pub line_numbers: Vec<usize>,
    pub snippet: String,
    #[serde(rename = "matchedPattern")]
    pub matched_pattern: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Usage {
    #[serde(rename = "inputTokens", default)]
    pub input_tokens: u64,
    #[serde(rename = "outputTokens", default)]
    pub output_tokens: u64,
    #[serde(rename = "cacheReadInputTokens", default)]
    pub cache_read_input_tokens: u64,
    #[serde(rename = "cacheCreationInputTokens", default)]
    pub cache_creation_input_tokens: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefusalReport {
    pub refused: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skipped: Option<Vec<RefusalSkipped>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefusalSkipped {
    #[serde(rename = "filePath", skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisEntry {
    #[serde(rename = "runId")]
    pub run_id: String,
    #[serde(rename = "investigatedAt")]
    pub investigated_at: String,
    #[serde(rename = "durationMs")]
    pub duration_ms: u64,
    #[serde(rename = "durationApiMs", skip_serializing_if = "Option::is_none")]
    pub duration_api_ms: Option<u64>,
    #[serde(rename = "agentType")]
    pub agent_type: String,
    pub model: String,
    #[serde(rename = "modelConfig", default)]
    pub model_config: IndexMap<String, serde_json::Value>,
    #[serde(rename = "agentSessionId", skip_serializing_if = "Option::is_none")]
    pub agent_session_id: Option<String>,
    #[serde(rename = "findingCount")]
    pub finding_count: usize,
    #[serde(rename = "numTurns", skip_serializing_if = "Option::is_none")]
    pub num_turns: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phase: Option<AnalysisPhase>,
    #[serde(rename = "costUsd", skip_serializing_if = "Option::is_none")]
    pub cost_usd: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage: Option<Usage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refusal: Option<RefusalReport>,
    #[serde(rename = "codexStderr", skip_serializing_if = "Option::is_none")]
    pub codex_stderr: Option<String>,
    #[serde(rename = "reinvestigateMarker", skip_serializing_if = "Option::is_none")]
    pub reinvestigate_marker: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AnalysisPhase {
    Process,
    Revalidate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Revalidation {
    pub verdict: RevalidationVerdict,
    pub reasoning: String,
    #[serde(rename = "adjustedSeverity", skip_serializing_if = "Option::is_none")]
    pub adjusted_severity: Option<Severity>,
    #[serde(rename = "revalidatedAt")]
    pub revalidated_at: String,
    #[serde(rename = "runId")]
    pub run_id: String,
    pub model: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Triage {
    pub priority: TriagePriority,
    pub exploitability: Exploitability,
    pub impact: Impact,
    pub reasoning: String,
    #[serde(rename = "triagedAt")]
    pub triaged_at: String,
    pub model: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Exploitability {
    Trivial,
    Moderate,
    Difficult,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Impact {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub severity: Severity,
    #[serde(rename = "vulnSlug")]
    pub vuln_slug: String,
    pub title: String,
    pub description: String,
    #[serde(rename = "lineNumbers")]
    pub line_numbers: Vec<usize>,
    pub recommendation: String,
    pub confidence: Confidence,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub triage: Option<Triage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revalidation: Option<Revalidation>,
    #[serde(rename = "producedByRunId", skip_serializing_if = "Option::is_none")]
    pub produced_by_run_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnershipContributor {
    pub email: String,
    pub name: String,
    pub github_username: String,
    pub score: f64,
    pub context: String,
    pub last_contrib: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnershipManager {
    pub email: String,
    pub slack_user_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnershipOncall {
    pub name: String,
    pub email: String,
    pub slack_user_id: String,
    pub github_username: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnershipEscalationTeam {
    pub name: String,
    pub slug: String,
    pub source: String,
    pub escalation_path_id: String,
    pub slack_channel_id: Option<String>,
    pub manager: OwnershipManager,
    pub current_oncall: OwnershipOncall,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnershipApprover {
    pub owner: String,
    pub owner_type: String,
    pub pattern: Option<String>,
    pub is_primary: bool,
    pub is_direct: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnershipData {
    pub contributors: Vec<OwnershipContributor>,
    #[serde(rename = "escalationTeams")]
    pub escalation_teams: Vec<OwnershipEscalationTeam>,
    pub approvers: Vec<OwnershipApprover>,
    #[serde(rename = "fetchedAt")]
    pub fetched_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitCommitter {
    pub name: String,
    pub email: String,
    pub date: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitInfo {
    #[serde(rename = "recentCommitters")]
    pub recent_committers: Vec<GitCommitter>,
    #[serde(rename = "enrichedAt")]
    pub enriched_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ownership: Option<OwnershipData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileRecord {
    #[serde(rename = "filePath")]
    pub file_path: String,
    #[serde(rename = "projectId")]
    pub project_id: String,

    #[serde(default)]
    pub candidates: Vec<CandidateMatch>,
    #[serde(rename = "lastScannedAt")]
    pub last_scanned_at: String,
    #[serde(rename = "lastScannedRunId")]
    pub last_scanned_run_id: String,
    #[serde(rename = "fileHash")]
    pub file_hash: String,

    #[serde(default)]
    pub findings: Vec<Finding>,
    #[serde(rename = "analysisHistory", default)]
    pub analysis_history: Vec<AnalysisEntry>,

    #[serde(rename = "gitInfo", skip_serializing_if = "Option::is_none")]
    pub git_info: Option<GitInfo>,

    pub status: FileStatus,
    #[serde(rename = "lockedByRunId", skip_serializing_if = "Option::is_none")]
    pub locked_by_run_id: Option<String>,
    #[serde(rename = "lockedAt", skip_serializing_if = "Option::is_none")]
    pub locked_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectConfig {
    #[serde(rename = "projectId")]
    pub project_id: String,
    #[serde(rename = "rootPath")]
    pub root_path: String,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "githubUrl", skip_serializing_if = "Option::is_none")]
    pub github_url: Option<String>,
}
