use crate::agents::shared::{ResponseEnvelope, detect_quota, extract_json};
use crate::agents::{
    AgentBackend, AgentBackendKind, InvestigateBatch, InvestigateOutput, InvestigateResult,
    RevalidateInput, RevalidatedFinding, TriageInput, TriagedFinding, Usage,
};
use crate::errors::{ProcessorError, QuotaExhausted};
use crate::prompt::{assemble_prompt, build_revalidate_prompt, build_triage_prompt};
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::json;
use std::time::Instant;

const DEFAULT_BASE: &str = "https://api.anthropic.com";
const DEFAULT_MODEL: &str = "claude-sonnet-4-6";

pub struct AnthropicBackend {
    api_key: String,
    model: String,
    base_url: String,
    client: reqwest::Client,
}

impl AnthropicBackend {
    pub fn new(api_key: String, model: String, base_url: Option<String>) -> Self {
        let model = if model.is_empty() {
            DEFAULT_MODEL.to_string()
        } else {
            model
        };
        Self {
            api_key,
            model,
            base_url: base_url.unwrap_or_else(|| DEFAULT_BASE.into()),
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(600))
                .build()
                .expect("reqwest client"),
        }
    }

    async fn call(&self, system: &str, user: &str) -> Result<(String, Usage), ProcessorError> {
        let url = format!("{}/v1/messages", self.base_url);
        let body = json!({
            "model": self.model,
            "max_tokens": 4096,
            "system": system,
            "temperature": 0,
            "messages": [{ "role": "user", "content": user }],
        });
        let resp = self
            .client
            .post(&url)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await?;

        let status = resp.status().as_u16();
        let text = resp.text().await?;

        if !(200..300).contains(&status) {
            if detect_quota(status, &text) {
                return Err(ProcessorError::Quota(QuotaExhausted {
                    backend: "anthropic".into(),
                    detail: text,
                }));
            }
            return Err(ProcessorError::Backend(format!(
                "anthropic {status}: {text}"
            )));
        }

        let parsed: AnthropicResponse = serde_json::from_str(&text)?;
        let mut content = String::new();
        for block in parsed.content {
            if let Some(t) = block.text {
                content.push_str(&t);
            }
        }
        let usage = Usage {
            input_tokens: parsed.usage.input_tokens.unwrap_or(0),
            output_tokens: parsed.usage.output_tokens.unwrap_or(0),
            cache_read_input_tokens: parsed.usage.cache_read_input_tokens.unwrap_or(0),
            cache_creation_input_tokens: parsed.usage.cache_creation_input_tokens.unwrap_or(0),
        };
        Ok((content, usage))
    }
}

#[derive(Debug, Deserialize)]
struct AnthropicResponse {
    #[serde(default)]
    content: Vec<AnthropicBlock>,
    #[serde(default)]
    usage: AnthropicUsage,
}

#[derive(Debug, Deserialize)]
struct AnthropicBlock {
    #[serde(default)]
    text: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct AnthropicUsage {
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    cache_read_input_tokens: Option<u64>,
    cache_creation_input_tokens: Option<u64>,
}

#[async_trait]
impl AgentBackend for AnthropicBackend {
    fn kind(&self) -> AgentBackendKind {
        AgentBackendKind::Anthropic
    }
    fn model(&self) -> &str {
        &self.model
    }

    async fn investigate(
        &self,
        batch: &InvestigateBatch,
    ) -> Result<InvestigateOutput, ProcessorError> {
        let (system, user) = assemble_prompt(batch);
        let start = Instant::now();
        let (text, usage) = self.call(&system, &user).await?;
        let duration_ms = start.elapsed().as_millis() as u64;

        let mut results = Vec::new();
        if let Some(json_str) = extract_json(&text) {
            if let Ok(env) = serde_json::from_str::<ResponseEnvelope>(json_str) {
                let mut by_file: std::collections::HashMap<String, Vec<_>> =
                    std::collections::HashMap::new();
                for ef in env.findings {
                    by_file
                        .entry(ef.file_path.clone())
                        .or_default()
                        .push(ef.finding);
                }
                for f in &batch.files {
                    let findings = by_file.remove(&f.path).unwrap_or_default();
                    results.push(InvestigateResult {
                        file_path: f.path.clone(),
                        findings,
                    });
                }
            }
        }
        if results.is_empty() {
            for f in &batch.files {
                results.push(InvestigateResult {
                    file_path: f.path.clone(),
                    findings: Vec::new(),
                });
            }
        }

        Ok(InvestigateOutput {
            results,
            usage,
            duration_ms,
            num_turns: 1,
            cost_usd: 0.0,
        })
    }

    async fn revalidate(
        &self,
        input: &RevalidateInput,
    ) -> Result<(Vec<RevalidatedFinding>, Usage, u64), ProcessorError> {
        let (system, user) = build_revalidate_prompt(input);
        let start = Instant::now();
        let (text, usage) = self.call(&system, &user).await?;
        let duration_ms = start.elapsed().as_millis() as u64;
        let mut out = Vec::new();
        if let Some(json_str) = extract_json(&text) {
            #[derive(Deserialize)]
            struct Env {
                #[serde(default)]
                revalidations: Vec<RevalidatedFinding>,
            }
            if let Ok(env) = serde_json::from_str::<Env>(json_str) {
                out = env.revalidations;
            }
        }
        Ok((out, usage, duration_ms))
    }

    async fn triage(
        &self,
        input: &TriageInput,
    ) -> Result<(TriagedFinding, Usage, u64), ProcessorError> {
        let (system, user) = build_triage_prompt(input);
        let start = Instant::now();
        let (text, usage) = self.call(&system, &user).await?;
        let duration_ms = start.elapsed().as_millis() as u64;
        let json_str = extract_json(&text)
            .ok_or_else(|| ProcessorError::Backend("triage: no JSON in response".into()))?;
        let parsed: TriagedFinding = serde_json::from_str(json_str)?;
        Ok((parsed, usage, duration_ms))
    }
}
