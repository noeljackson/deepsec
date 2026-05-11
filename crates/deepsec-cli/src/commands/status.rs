use crate::config_loader::Context;
use anyhow::Result;
use clap::Args as ClapArgs;
use colored::Colorize;
use deepsec_core::{FileStatus, runs::list_runs, store::load_all_file_records};

#[derive(Debug, ClapArgs)]
pub struct Args {
    #[arg(long)]
    pub project_id: String,
    /// Show last N runs.
    #[arg(long, default_value_t = 5)]
    pub recent: usize,
}

pub fn run(args: Args, ctx: &Context) -> Result<()> {
    let records = load_all_file_records(&ctx.data_root, &args.project_id)?;
    let mut pending = 0usize;
    let mut analyzed = 0usize;
    let mut processing = 0usize;
    let mut error = 0usize;
    let mut total_candidates = 0usize;
    let mut total_findings = 0usize;
    for r in &records {
        match r.status {
            FileStatus::Pending => pending += 1,
            FileStatus::Analyzed => analyzed += 1,
            FileStatus::Processing => processing += 1,
            FileStatus::Error => error += 1,
        }
        total_candidates += r.candidates.len();
        total_findings += r.findings.len();
    }
    println!("{} {}", "project".bold(), args.project_id);
    println!("  records:    {}", records.len());
    println!("  pending:    {pending}");
    println!("  analyzed:   {analyzed}");
    println!("  processing: {processing}");
    println!("  error:      {error}");
    println!("  candidates: {total_candidates}");
    println!("  findings:   {total_findings}");

    let runs = list_runs(&ctx.data_root, &args.project_id)?;
    if !runs.is_empty() {
        println!("\n{}", "recent runs".bold());
        for r in runs.iter().take(args.recent) {
            println!(
                "  {} [{:?}/{:?}] candidates={} findings={}",
                r.run_id,
                r.run_type,
                r.phase,
                r.stats.candidates_found.unwrap_or(0),
                r.stats.findings_count.unwrap_or(0)
            );
        }
    }
    Ok(())
}
