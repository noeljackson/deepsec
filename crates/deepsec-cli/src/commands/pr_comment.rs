use crate::config_loader::Context;
use anyhow::{Result, anyhow};
use clap::Args as ClapArgs;
use deepsec_core::{
    FileRecord, Finding, RevalidationVerdict, Severity, runs::list_runs,
    store::load_all_file_records,
};

#[derive(Debug, ClapArgs)]
pub struct Args {
    #[arg(long)]
    pub project_id: String,
    /// Run id to filter net-new findings by. Defaults to the most recent
    /// `process` run.
    #[arg(long)]
    pub run_id: Option<String>,
    /// Drop revalidated false-positive / fixed findings.
    #[arg(long, default_value_t = true)]
    pub real_only: bool,
    /// Write to this path. Defaults to stdout.
    #[arg(long)]
    pub output: Option<std::path::PathBuf>,
    /// Don't render anything if there are no net-new findings.
    #[arg(long)]
    pub skip_empty: bool,
}

pub fn run(args: Args, ctx: &Context) -> Result<()> {
    let run_id = match args.run_id {
        Some(id) => id,
        None => {
            let runs = list_runs(&ctx.data_root, &args.project_id)?;
            runs.into_iter()
                .find(|r| matches!(r.run_type, deepsec_core::RunType::Process))
                .map(|r| r.run_id)
                .ok_or_else(|| anyhow!("no recent process run found"))?
        }
    };

    let records = load_all_file_records(&ctx.data_root, &args.project_id)?;
    let mut rows: Vec<(String, &FileRecord, &Finding)> = Vec::new();
    for rec in &records {
        for f in &rec.findings {
            if f.produced_by_run_id.as_deref() != Some(run_id.as_str()) {
                continue;
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

    if rows.is_empty() && args.skip_empty {
        return Ok(());
    }

    rows.sort_by(|a, b| b.2.severity.rank().cmp(&a.2.severity.rank()));

    let body = render(&run_id, &rows);
    if let Some(out) = args.output {
        if let Some(parent) = out.parent() {
            fs_err::create_dir_all(parent)?;
        }
        fs_err::write(&out, &body)?;
    } else {
        println!("{body}");
    }
    Ok(())
}

fn render(run_id: &str, rows: &[(String, &FileRecord, &Finding)]) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    if rows.is_empty() {
        writeln!(
            &mut out,
            "## deepsec — no net-new findings for run `{run_id}` :white_check_mark:"
        )
        .ok();
        return out;
    }
    let mut by_sev: std::collections::BTreeMap<Severity, usize> = std::collections::BTreeMap::new();
    for (_, _, f) in rows {
        *by_sev.entry(f.severity).or_default() += 1;
    }
    writeln!(
        &mut out,
        "## deepsec — {} net-new finding{} for run `{}`",
        rows.len(),
        if rows.len() == 1 { "" } else { "s" },
        run_id
    )
    .ok();
    let mut parts: Vec<String> = Vec::new();
    for (sev, n) in by_sev.iter().rev() {
        parts.push(format!("{n} × {}", sev.as_str()));
    }
    writeln!(&mut out, "{}\n", parts.join(" · ")).ok();
    for (path, _rec, f) in rows {
        writeln!(
            &mut out,
            "### `{}` — {} **{}**",
            badge(f.severity),
            f.severity.as_str(),
            f.title
        )
        .ok();
        writeln!(&mut out, "- file: `{path}` (lines {:?})", f.line_numbers).ok();
        writeln!(&mut out, "- slug: `{}`", f.vuln_slug).ok();
        writeln!(&mut out, "- confidence: `{:?}`", f.confidence).ok();
        if let Some(rv) = &f.revalidation {
            writeln!(&mut out, "- revalidation: `{:?}`", rv.verdict).ok();
        }
        writeln!(&mut out, "\n{}\n", f.description).ok();
        writeln!(&mut out, "**Fix:** {}\n", f.recommendation).ok();
    }
    out
}

fn badge(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical => "CRIT",
        Severity::High | Severity::HighBug => "HIGH",
        Severity::Medium => "MED ",
        Severity::Bug => "BUG ",
        Severity::Low => "LOW ",
    }
}
