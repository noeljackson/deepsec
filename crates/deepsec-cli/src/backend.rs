use anyhow::{Context, Result, anyhow};
use deepsec_processor::agents::{AgentBackend, AgentBackendKind, BackendChoice, make_backend};

pub fn resolve_backend(
    agent_arg: Option<&str>,
    model_arg: Option<&str>,
    default: Option<&str>,
) -> Result<Box<dyn AgentBackend>> {
    let raw = agent_arg
        .or(default)
        .unwrap_or("anthropic");
    let kind = AgentBackendKind::from_str(raw)
        .ok_or_else(|| anyhow!("unknown agent backend: '{raw}' (try 'anthropic' or 'openai')"))?;

    let (api_key_env, base_env) = match kind {
        AgentBackendKind::Anthropic => ("ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL"),
        AgentBackendKind::OpenAi => ("OPENAI_API_KEY", "OPENAI_BASE_URL"),
    };
    let api_key = std::env::var(api_key_env)
        .with_context(|| format!("missing {api_key_env} env var"))?;
    let base_url = std::env::var(base_env).ok();

    let model = model_arg.map(String::from).unwrap_or_default();
    Ok(make_backend(BackendChoice {
        kind,
        model,
        api_key,
        base_url,
    }))
}
