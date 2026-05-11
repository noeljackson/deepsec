use super::core_prompt::CORE_PROMPT;
use super::highlights::highlight_for_tag;
use super::slug_notes::note_for_slug;
use crate::agents::InvestigateBatch;
use std::fmt::Write;

/// Assemble (system, user) prompts for one investigation batch.
pub fn assemble_prompt(batch: &InvestigateBatch) -> (String, String) {
    let mut system = String::with_capacity(CORE_PROMPT.len() + 4096);
    system.push_str(CORE_PROMPT);

    let highlights: Vec<&str> = batch
        .tech_tags
        .iter()
        .filter_map(|t| highlight_for_tag(t))
        .collect();
    if !highlights.is_empty() {
        system.push_str("\nFramework-specific context:\n");
        for h in highlights {
            writeln!(&mut system, "- {h}").ok();
        }
    }

    let mut notes: Vec<(String, &str)> = batch
        .slug_notes
        .iter()
        .filter_map(|(s, _)| note_for_slug(s).map(|n| (s.clone(), n)))
        .collect();
    notes.sort_by(|a, b| a.0.cmp(&b.0));
    notes.dedup_by(|a, b| a.0 == b.0);
    if !notes.is_empty() {
        system.push_str("\nCandidate-slug reasoning hints:\n");
        for (slug, note) in notes {
            writeln!(&mut system, "- {slug}: {note}").ok();
        }
    }

    if let Some(info) = &batch.project_info {
        system.push_str("\nProject context:\n");
        system.push_str(info.trim());
        system.push('\n');
    }
    if let Some(extra) = &batch.prompt_append {
        system.push('\n');
        system.push_str(extra.trim());
        system.push('\n');
    }

    let mut user = String::new();
    user.push_str("Review these files for exploitable vulnerabilities.\n\n");
    for f in &batch.files {
        writeln!(&mut user, "===== FILE: {} =====", f.path).ok();
        if !f.candidates.is_empty() {
            user.push_str("Candidate matches (regex-derived, may be noisy):\n");
            for c in &f.candidates {
                writeln!(
                    &mut user,
                    "  - slug={} lines={:?} matched=\"{}\"",
                    c.vuln_slug, c.line_numbers, c.matched_pattern
                )
                .ok();
            }
        }
        user.push_str("Code:\n");
        for (i, line) in f.content.split('\n').enumerate() {
            writeln!(&mut user, "{:5} {line}", i + 1).ok();
        }
        user.push('\n');
    }
    user.push_str("\nReturn ONLY the JSON object described in the system prompt.");
    (system, user)
}
