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

const DEFAULT_BASE: &str = "https://api.openai.com";
const DEFAULT_MODEL: &str = "gpt-4.1-mini";

pub struct OpenAiBackend {
    api_key: String,
    model: String,
    base_url: String,
    client: reqwest::Client,
}

impl OpenAiBackend {
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

    /// Uses the chat-completions endpoint with JSON-mode response format.
    /// Works for both OpenAI and OpenAI-compatible gateways (Azure
    /// OpenAI, OpenRouter, vLLM, etc.) — point at them via `base_url`.
    async fn call(&self, system: &str, user: &str) -> Result<(String, Usage), ProcessorError> {
        let url = format!("{}/v1/chat/completions", self.base_url);
        let body = json!({
            "model": self.model,
            "temperature": 0,
            "response_format": { "type": "json_object" },
            "messages": [
                { "role": "system", "content": system },
                { "role": "user", "content": user }
            ],
        });
        let resp = self
            .client
            .post(&url)
            .header("authorization", format!("Bearer {}", self.api_key))
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await?;

        let status = resp.status().as_u16();
        let text = resp.text().await?;
        if !(200..300).contains(&status) {
            if detect_quota(status, &text) {
                return Err(ProcessorError::Quota(QuotaExhausted {
                    backend: "openai".into(),
                    detail: text,
                }));
            }
            return Err(ProcessorError::Backend(format!("openai {status}: {text}")));
        }

        let parsed: OpenAiResponse = serde_json::from_str(&text)?;
        let content = parsed
            .choices
            .into_iter()
            .next()
            .map(|c| c.message.content)
            .unwrap_or_default();
        let usage = Usage {
            input_tokens: parsed.usage.as_ref().and_then(|u| u.prompt_tokens).unwrap_or(0),
            output_tokens: parsed
                .usage
                .as_ref()
                .and_then(|u| u.completion_tokens)
                .unwrap_or(0),
            cache_read_input_tokens: parsed
                .usage
                .as_ref()
                .and_then(|u| u.cached_tokens)
                .unwrap_or(0),
            cache_creation_input_tokens: 0,
        };
        Ok((content, usage))
    }
}

#[derive(Debug, Deserialize)]
struct OpenAiResponse {
    choices: Vec<Choice>,
    #[serde(default)]
    usage: Option<UsageBlock>,
}

#[derive(Debug, Deserialize)]
struct Choice {
    message: Message,
}

#[derive(Debug, Deserialize)]
struct Message {
    #[serde(default)]
    content: String,
}

#[derive(Debug, Deserialize)]
struct UsageBlock {
    prompt_tokens: Option<u64>,
    completion_tokens: Option<u64>,
    #[serde(default)]
    cached_tokens: Option<u64>,
}

#[async_trait]
impl AgentBackend for OpenAiBackend {
    fn kind(&self) -> AgentBackendKind {
        AgentBackendKind::OpenAi
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
        let json_str = extract_json(&text).unwrap_or(&text);
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
        } else {
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
        let json_str = extract_json(&text).unwrap_or(&text);
        #[derive(Deserialize)]
        struct Env {
            #[serde(default)]
            revalidations: Vec<RevalidatedFinding>,
        }
        let out = serde_json::from_str::<Env>(json_str)
            .map(|e| e.revalidations)
            .unwrap_or_default();
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
