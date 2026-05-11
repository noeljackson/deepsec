use crate::config_loader::Context;
use anyhow::Result;
use clap::Args as ClapArgs;
use colored::Colorize;

#[derive(Debug, ClapArgs)]
pub struct Args {
    /// Backend to validate. Defaults to the configured default_agent.
    #[arg(long)]
    pub agent: Option<String>,
}

pub fn run(args: Args, ctx: &Context) -> Result<()> {
    let default = ctx.config.as_ref().and_then(|c| c.default_agent.as_deref());
    let report = crate::preflight::check(args.agent.as_deref().or(default))?;
    println!(
        "{} backend={} api_key=set base_url={}",
        "preflight ok".bold().green(),
        report.backend.as_str(),
        report
            .base_url
            .as_deref()
            .unwrap_or("<default>")
    );
    if ctx.config.is_some() {
        println!("  config: {}", ctx.config_path.as_ref().unwrap().display());
    } else {
        println!(
            "  {}: no deepsec.config.toml found",
            "warn".yellow()
        );
    }
    println!("  data root: {}", ctx.data_root.as_path().display());
    Ok(())
}
