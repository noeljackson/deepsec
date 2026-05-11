use crate::agents::RevalidateInput;
use std::fmt::Write;

pub fn build_revalidate_prompt(input: &RevalidateInput) -> (String, String) {
    let system = r#"You are revalidating previously reported security findings against the CURRENT state of the file. For each finding decide one of:
  - "true-positive": the vulnerability is still present and exploitable
  - "false-positive": the original report was wrong
  - "fixed": the code has been changed and the issue is no longer present
  - "uncertain": you can't tell from this file alone

Return JSON only:
{
  "revalidations": [
    { "index": <number>, "verdict": "true-positive", "reasoning": "...", "adjusted_severity": "HIGH" }
  ]
}

`adjusted_severity` is optional and only set when you want to change the original severity.
"#;

    let mut user = String::new();
    writeln!(&mut user, "File: {}", input.file_path).ok();
    user.push_str("Code:\n");
    for (i, line) in input.file_content.split('\n').enumerate() {
        writeln!(&mut user, "{:5} {line}", i + 1).ok();
    }
    user.push_str("\nFindings to revalidate:\n");
    for f in &input.findings {
        writeln!(
            &mut user,
            "[{}] severity={} slug={} lines={:?} title={}",
            f.index,
            f.severity.as_str(),
            f.vuln_slug,
            f.line_numbers,
            f.title
        )
        .ok();
        writeln!(&mut user, "    description: {}", f.description).ok();
    }
    (system.to_string(), user)
}
