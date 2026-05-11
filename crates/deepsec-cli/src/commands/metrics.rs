use crate::config_loader::Context;
use anyhow::Result;
use clap::Args as ClapArgs;
use colored::Colorize;
use deepsec_core::{RevalidationVerdict, runs::list_runs, store::load_all_file_records};
use std::collections::BTreeMap;

#[derive(Debug, ClapArgs)]
pub struct Args {
    #[arg(long)]
    pub project_id: String,
}

pub fn run(args: Args, ctx: &Context) -> Result<()> {
    let records = load_all_file_records(&ctx.data_root, &args.project_id)?;
    let runs = list_runs(&ctx.data_root, &args.project_id)?;

    let mut total_cost = 0.0;
    let mut total_in = 0u64;
    let mut total_out = 0u64;
    let mut total_duration = 0u64;
    for r in &runs {
        total_cost += r.stats.total_cost_usd.unwrap_or(0.0);
        total_in += r.stats.total_input_tokens.unwrap_or(0);
        total_out += r.stats.total_output_tokens.unwrap_or(0);
        total_duration += r.stats.total_duration_ms.unwrap_or(0);
    }

    let mut by_slug: BTreeMap<String, (usize, usize, usize)> = BTreeMap::new();
    let mut tp = 0;
    let mut fp = 0;
    let mut fx = 0;
    let mut un = 0;
    let mut total = 0;

    for rec in &records {
        for f in &rec.findings {
            total += 1;
            let entry = by_slug.entry(f.vuln_slug.clone()).or_default();
            entry.0 += 1;
            if let Some(rv) = &f.revalidation {
                match rv.verdict {
                    RevalidationVerdict::TruePositive => {
                        tp += 1;
                        entry.1 += 1;
                    }
                    RevalidationVerdict::FalsePositive => {
                        fp += 1;
                        entry.2 += 1;
                    }
                    RevalidationVerdict::Fixed => fx += 1,
                    RevalidationVerdict::Uncertain => un += 1,
                    RevalidationVerdict::AcceptedRisk => tp += 1,
                }
            }
        }
    }

    println!("{}", "metrics".bold());
    println!("  runs:            {}", runs.len());
    println!("  total cost:      ${:.4}", total_cost);
    println!("  input tokens:    {total_in}");
    println!("  output tokens:   {total_out}");
    println!("  total runtime:   {:.1}s", total_duration as f64 / 1000.0);
    println!();
    println!("  findings:        {total}");
    println!("    TP:            {tp}");
    println!("    FP:            {fp}");
    println!("    fixed:         {fx}");
    println!("    uncertain:     {un}");
    println!();
    println!("  by slug:");
    let mut entries: Vec<_> = by_slug.iter().collect();
    entries.sort_by(|a, b| b.1.0.cmp(&a.1.0));
    for (slug, (n, tp, fp)) in entries.into_iter().take(30) {
        println!("    {slug:<42} total={n:<5} TP={tp:<4} FP={fp:<4}");
    }
    Ok(())
}
