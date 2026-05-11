use crate::agents::ProducedFinding;
use serde::Deserialize;

/// Findings come back as JSON shaped roughly like:
///   { "findings": [{ "filePath": "...", "severity": "HIGH", ... }, ...] }
/// We accept a few common variants for resilience across backends.
#[derive(Debug, Deserialize)]
pub struct ResponseEnvelope {
    #[serde(default)]
    pub findings: Vec<EnvelopeFinding>,
    #[serde(default)]
    pub refusal: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct EnvelopeFinding {
    #[serde(rename = "filePath", alias = "file_path", alias = "path")]
    pub file_path: String,
    #[serde(flatten)]
    pub finding: ProducedFinding,
}

/// Extract a JSON object from a response that may be wrapped in
/// ```json ... ``` fences or contain leading prose.
pub fn extract_json(body: &str) -> Option<&str> {
    if let Some(start) = body.find("```json") {
        let rest = &body[start + "```json".len()..];
        if let Some(end) = rest.find("```") {
            return Some(rest[..end].trim());
        }
    }
    if let Some(start) = body.find("```") {
        let rest = &body[start + 3..];
        if let Some(end) = rest.find("```") {
            return Some(rest[..end].trim());
        }
    }
    // try to grab the outermost {...}
    let first = body.find('{')?;
    let last = body.rfind('}')?;
    if last > first {
        Some(body[first..=last].trim())
    } else {
        None
    }
}

pub fn detect_quota(status: u16, body: &str) -> bool {
    if status == 429 {
        return true;
    }
    let lower = body.to_lowercase();
    lower.contains("quota") || lower.contains("rate limit") || lower.contains("insufficient_quota")
}
