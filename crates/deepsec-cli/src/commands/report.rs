use crate::config_loader::Context;
use anyhow::Result;
use clap::Args as ClapArgs;
use colored::Colorize;
use deepsec_core::{
    FileRecord, Finding, RevalidationVerdict, Severity, report_csv_path, report_json_path,
    report_md_path, store::load_all_file_records,
};

#[derive(Debug, ClapArgs)]
pub struct Args {
    #[arg(long)]
    pub project_id: String,
    /// Minimum severity to include.
    #[arg(long)]
    pub min_severity: Option<String>,
    /// Only include findings produced by this run.
    #[arg(long)]
    pub run_id: Option<String>,
    /// Exclude findings revalidated as false-positive / fixed.
    #[arg(long)]
    pub real_only: bool,
}

pub fn run(args: Args, ctx: &Context) -> Result<()> {
    let records = load_all_file_records(&ctx.data_root, &args.project_id)?;
    let min_sev = args
        .min_severity
        .as_deref()
        .map(parse_severity)
        .transpose()?
        .unwrap_or(Severity::Low);

    let mut rows: Vec<(String, &FileRecord, &Finding)> = Vec::new();
    for rec in &records {
        for f in &rec.findings {
            if f.severity.rank() < min_sev.rank() {
                continue;
            }
            if let Some(rid) = &args.run_id {
                if f.produced_by_run_id.as_deref() != Some(rid.as_str()) {
                    continue;
                }
            }
            if args.real_only {
                if let Some(rv) = &f.revalidation {
                    if matches!(
                        rv.verdict,
                        RevalidationVerdict::FalsePositive | RevalidationVerdict::Fixed
                    ) {
                        continue;
                    }
                }
            }
            rows.push((rec.file_path.clone(), rec, f));
        }
    }
    rows.sort_by(|a, b| b.2.severity.rank().cmp(&a.2.severity.rank()));

    let md_path = report_md_path(&ctx.data_root, &args.project_id, args.run_id.as_deref())?;
    let json_path = report_json_path(&ctx.data_root, &args.project_id, args.run_id.as_deref())?;
    let csv_path = report_csv_path(&ctx.data_root, &args.project_id, args.run_id.as_deref())?;
    if let Some(p) = md_path.parent() {
        fs_err::create_dir_all(p)?;
    }
    fs_err::write(&md_path, render_markdown(&args.project_id, &rows))?;
    fs_err::write(&json_path, render_json(&rows)?)?;
    fs_err::write(&csv_path, render_csv(&rows)?)?;

    println!(
        "{} findings={} → {}, {}, {}",
        "report".bold().green(),
        rows.len(),
        md_path.display(),
        json_path.display(),
        csv_path.display()
    );
    Ok(())
}

fn parse_severity(s: &str) -> Result<Severity> {
    Ok(match s.to_uppercase().as_str() {
        "CRITICAL" => Severity::Critical,
        "HIGH" => Severity::High,
        "HIGH_BUG" => Severity::HighBug,
        "MEDIUM" => Severity::Medium,
        "BUG" => Severity::Bug,
        "LOW" => Severity::Low,
        _ => anyhow::bail!("unknown severity: {s}"),
    })
}

fn render_markdown(project_id: &str, rows: &[(String, &FileRecord, &Finding)]) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    writeln!(&mut out, "# deepsec report — {project_id}\n").ok();
    writeln!(&mut out, "Total findings: {}\n", rows.len()).ok();
    for (path, _rec, f) in rows {
        writeln!(
            &mut out,
            "## [{}] {} — `{}`",
            f.severity.as_str(),
            f.title,
            f.vuln_slug
        )
        .ok();
        writeln!(&mut out, "- file: `{}`", path).ok();
        writeln!(&mut out, "- lines: {:?}", f.line_numbers).ok();
        writeln!(&mut out, "- confidence: {:?}", f.confidence).ok();
        if let Some(r) = &f.revalidation {
            writeln!(&mut out, "- revalidation: {:?}", r.verdict).ok();
        }
        if let Some(t) = &f.triage {
            writeln!(
                &mut out,
                "- triage: priority={:?} exploitability={:?} impact={:?}",
                t.priority, t.exploitability, t.impact
            )
            .ok();
        }
        writeln!(&mut out, "\n{}\n", f.description).ok();
        writeln!(&mut out, "**Fix:** {}\n", f.recommendation).ok();
    }
    out
}

fn render_json(rows: &[(String, &FileRecord, &Finding)]) -> Result<String> {
    let payload: Vec<_> = rows
        .iter()
        .map(|(path, _, f)| {
            serde_json::json!({
                "filePath": path,
                "finding": f,
            })
        })
        .collect();
    Ok(serde_json::to_string_pretty(&payload)?)
}

fn render_csv(rows: &[(String, &FileRecord, &Finding)]) -> Result<String> {
    let mut wtr = csv::Writer::from_writer(Vec::new());
    wtr.write_record(["file", "severity", "slug", "lines", "title", "confidence", "verdict"])?;
    for (path, _, f) in rows {
        let lines: Vec<String> = f.line_numbers.iter().map(|n| n.to_string()).collect();
        wtr.write_record([
            path,
            f.severity.as_str(),
            &f.vuln_slug,
            &lines.join(";"),
            &f.title,
            &format!("{:?}", f.confidence),
            &f.revalidation
                .as_ref()
                .map(|r| format!("{:?}", r.verdict))
                .unwrap_or_default(),
        ])?;
    }
    Ok(String::from_utf8(wtr.into_inner()?)?)
}
