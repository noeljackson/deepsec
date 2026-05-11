//! deepsec-processor: AI enrichment pipeline.
//!
//! Backends are pluggable via the [`AgentBackend`] trait. Two
//! implementations are bundled:
//!   - [`agents::anthropic::AnthropicBackend`] — Anthropic Messages API
//!   - [`agents::openai::OpenAiBackend`]       — OpenAI Responses API
//!
//! Both speak HTTP directly (`reqwest`) so the Rust port has no Node
//! SDK dependency.

pub mod agents;
pub mod batch;
pub mod prompt;
pub mod process;
pub mod revalidate;
pub mod triage;
pub mod errors;

pub use agents::{
    AgentBackend, AgentBackendKind, BackendChoice, InvestigateBatch, InvestigateOutput,
    InvestigateResult, ProducedFinding, RevalidateInput, RevalidatedFinding,
    TriageInput, TriagedFinding, Usage,
};
pub use batch::batch_records;
pub use errors::{ProcessorError, QuotaExhausted};
pub use process::{ProcessOptions, ProcessOutcome, run_process};
pub use prompt::{CORE_PROMPT, assemble_prompt};
pub use revalidate::{RevalidateOptions, RevalidateOutcome, run_revalidate};
pub use triage::{TriageOptions, TriageOutcome, run_triage};
