use crate::agents::TriageInput;
use std::fmt::Write;

pub fn build_triage_prompt(input: &TriageInput) -> (String, String) {
    let system = r#"You are triaging one security finding. Assign:
  - priority: "P0" (drop everything) | "P1" (this sprint) | "P2" (backlog) | "skip" (not worth fixing)
  - exploitability: "trivial" | "moderate" | "difficult"
  - impact: "critical" | "high" | "medium" | "low"
  - reasoning: one short paragraph.

Return JSON only:
{ "priority": "P1", "exploitability": "moderate", "impact": "high", "reasoning": "..." }
"#;

    let mut user = String::new();
    writeln!(&mut user, "File: {}", input.file_path).ok();
    writeln!(
        &mut user,
        "severity={} slug={} lines={:?} title={}",
        input.finding.severity.as_str(),
        input.finding.vuln_slug,
        input.finding.line_numbers,
        input.finding.title,
    )
    .ok();
    writeln!(&mut user, "description: {}", input.finding.description).ok();
    (system.to_string(), user)
}
