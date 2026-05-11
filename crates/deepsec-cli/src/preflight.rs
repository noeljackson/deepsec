//! Auto-run sanity check before AI commands. Verifies the env vars
//! for the resolved backend are present. Surfaces a clear error
//! instead of a 401 buried in a wrapped reqwest error.

use anyhow::{Context, Result, anyhow};
use deepsec_processor::agents::AgentBackendKind;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct PreflightReport {
    pub backend: AgentBackendKind,
    pub api_key_present: bool,
    pub base_url: Option<String>,
}

pub fn check(agent: Option<&str>) -> Result<PreflightReport> {
    let raw = agent.unwrap_or("anthropic");
    let kind = AgentBackendKind::from_str(raw)
        .ok_or_else(|| anyhow!("unknown agent backend: '{raw}' (try 'anthropic' or 'openai')"))?;
    let (api_key_env, base_env) = match kind {
        AgentBackendKind::Anthropic => ("ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL"),
        AgentBackendKind::OpenAi => ("OPENAI_API_KEY", "OPENAI_BASE_URL"),
    };
    std::env::var(api_key_env)
        .with_context(|| format!("missing {api_key_env} env var (preflight)"))?;
    Ok(PreflightReport {
        backend: kind,
        api_key_present: true,
        base_url: std::env::var(base_env).ok(),
    })
}
