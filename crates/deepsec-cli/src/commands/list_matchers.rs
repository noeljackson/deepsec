use anyhow::Result;
use colored::Colorize;
use deepsec_scanner::MatcherRegistry;

pub fn run() -> Result<()> {
    let reg = MatcherRegistry::with_builtin()?;
    println!("{} matchers", reg.len().to_string().bold());
    for m in reg.iter() {
        println!(
            "  {:<40} {:<8} {}",
            m.slug().bold(),
            format!("{:?}", m.noise_tier()).to_lowercase().dimmed(),
            m.description()
        );
    }
    Ok(())
}
