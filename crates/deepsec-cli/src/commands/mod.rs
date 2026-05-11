pub mod init;
pub mod init_project;
pub mod list_matchers;
pub mod metrics;
pub mod process;
pub mod report;
pub mod revalidate;
pub mod scan;
pub mod status;
pub mod triage;

pub fn scan_split_csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(|t| t.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}
