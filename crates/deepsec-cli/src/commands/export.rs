use crate::config_loader::Context;
use anyhow::Result;
use clap::Args as ClapArgs;
use deepsec_core::{RevalidationVerdict, Severity, store::load_all_file_records};

#[derive(Debug, ClapArgs)]
pub struct Args {
    #[arg(long)]
    pub project_id: String,
    /// Minimum severity to include.
    #[arg(long)]
    pub min_severity: Option<String>,
    /// Only export findings produced by this run.
    #[arg(long)]
    pub run_id: Option<String>,
    /// Verdict filter (true-positive, false-positive, fixed, uncertain,
    /// accepted-risk).
    #[arg(long)]
    pub verdict: Option<String>,
    /// Only this vulnerability slug.
    #[arg(long)]
    pub slug: Option<String>,
    /// File-path prefix filter.
    #[arg(long)]
    pub prefix: Option<String>,
    /// Write JSON to this path instead of stdout.
    #[arg(long)]
    pub output: Option<std::path::PathBuf>,
}

pub fn run(args: Args, ctx: &Context) -> Result<()> {
    let records = load_all_file_records(&ctx.data_root, &args.project_id)?;
    let min_sev = args
        .min_severity
        .as_deref()
        .map(parse_severity)
        .transpose()?
        .unwrap_or(Severity::Low);
    let want_verdict = args.verdict.as_deref().map(parse_verdict).transpose()?;

    let mut rows = Vec::new();
    for rec in &records {
        if let Some(p) = &args.prefix {
            if !rec.file_path.starts_with(p) {
                continue;
            }
        }
        for f in &rec.findings {
            if f.severity.rank() < min_sev.rank() {
                continue;
            }
            if let Some(rid) = &args.run_id {
                if f.produced_by_run_id.as_deref() != Some(rid.as_str()) {
                    continue;
                }
            }
            if let Some(slug) = &args.slug {
                if f.vuln_slug != *slug {
                    continue;
                }
            }
            if let Some(v) = want_verdict {
                let actual = f.revalidation.as_ref().map(|r| r.verdict);
                if actual != Some(v) {
                    continue;
                }
            }
            rows.push(serde_json::json!({
                "filePath": rec.file_path,
                "finding": f,
                "gitInfo": rec.git_info,
            }));
        }
    }

    let body = serde_json::to_string_pretty(&rows)?;
    if let Some(out) = args.output {
        if let Some(parent) = out.parent() {
            fs_err::create_dir_all(parent)?;
        }
        fs_err::write(&out, &body)?;
        eprintln!("wrote {} findings to {}", rows.len(), out.display());
    } else {
        println!("{body}");
    }
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

fn parse_verdict(s: &str) -> Result<RevalidationVerdict> {
    Ok(match s.to_lowercase().as_str() {
        "true-positive" | "tp" => RevalidationVerdict::TruePositive,
        "false-positive" | "fp" => RevalidationVerdict::FalsePositive,
        "fixed" => RevalidationVerdict::Fixed,
        "uncertain" => RevalidationVerdict::Uncertain,
        "accepted-risk" => RevalidationVerdict::AcceptedRisk,
        _ => anyhow::bail!("unknown verdict: {s}"),
    })
}
