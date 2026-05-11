use clap::{Parser, Subcommand};

mod backend;
mod commands;
mod config_loader;
mod file_sources;
mod preflight;

#[derive(Parser, Debug)]
#[command(
    name = "deepsec",
    version,
    about = "Multi-pass security scanner with AI-assisted investigation",
    propagate_version = true
)]
struct Cli {
    /// Path to deepsec.config.toml. If omitted, searched starting from cwd.
    #[arg(long, global = true, env = "DEEPSEC_CONFIG")]
    config: Option<std::path::PathBuf>,

    /// Override the on-disk data root (default: ./data).
    #[arg(long, global = true, env = "DEEPSEC_DATA_ROOT")]
    data_dir: Option<std::path::PathBuf>,

    /// Increase log verbosity.
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Initialize a deepsec.config.toml in the current directory.
    Init(commands::init::Args),
    /// Initialize a new project entry in an existing config.
    InitProject(commands::init_project::Args),
    /// Run the regex scanner over a project.
    Scan(commands::scan::Args),
    /// Investigate pending candidates with an AI backend.
    Process(commands::process::Args),
    /// Re-verify existing findings against the current code.
    Revalidate(commands::revalidate::Args),
    /// Assign priority / exploitability / impact to findings.
    Triage(commands::triage::Args),
    /// Show pending / analyzed counts and recent runs.
    Status(commands::status::Args),
    /// Render a project report (markdown + JSON + CSV).
    Report(commands::report::Args),
    /// Filtered JSON export of findings.
    Export(commands::export::Args),
    /// Enrich FileRecords with git committer history.
    Enrich(commands::enrich::Args),
    /// Aggregate metrics across all runs.
    Metrics(commands::metrics::Args),
    /// Render a PR comment markdown for net-new findings.
    PrComment(commands::pr_comment::Args),
    /// `git add data/ && git commit` the on-disk mirror.
    DataCommit(commands::data_commit::Args),
    /// Validate environment for the chosen backend.
    Preflight(commands::preflight::Args),
    /// Print bundled matcher slugs.
    ListMatchers,
}

fn main() {
    let cli = Cli::parse();
    init_logging(cli.verbose);
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let result = rt.block_on(dispatch(cli));
    if let Err(e) = result {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

async fn dispatch(cli: Cli) -> anyhow::Result<()> {
    let ctx = config_loader::Context::from_cli(cli.config.as_deref(), cli.data_dir.as_deref())?;
    match cli.command {
        Cmd::Init(a) => commands::init::run(a, &ctx),
        Cmd::InitProject(a) => commands::init_project::run(a, &ctx),
        Cmd::Scan(a) => commands::scan::run(a, &ctx),
        Cmd::Process(a) => commands::process::run(a, &ctx).await,
        Cmd::Revalidate(a) => commands::revalidate::run(a, &ctx).await,
        Cmd::Triage(a) => commands::triage::run(a, &ctx).await,
        Cmd::Status(a) => commands::status::run(a, &ctx),
        Cmd::Report(a) => commands::report::run(a, &ctx),
        Cmd::Export(a) => commands::export::run(a, &ctx),
        Cmd::Enrich(a) => commands::enrich::run(a, &ctx),
        Cmd::Metrics(a) => commands::metrics::run(a, &ctx),
        Cmd::PrComment(a) => commands::pr_comment::run(a, &ctx),
        Cmd::DataCommit(a) => commands::data_commit::run(a, &ctx),
        Cmd::Preflight(a) => commands::preflight::run(a, &ctx),
        Cmd::ListMatchers => commands::list_matchers::run(),
    }
}

fn init_logging(verbose: u8) {
    let level = match verbose {
        0 => "warn,deepsec=info",
        1 => "info",
        _ => "debug",
    };
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level)),
        )
        .with_target(false)
        .compact()
        .try_init();
}
