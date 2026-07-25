use std::{collections::BTreeMap, process::Command};

fn run_profile(executable: &str, values: BTreeMap<String, String>) {
    // A child inherits BROKER_TOKEN and BROKER_BASIC_* from this process.
    let _ = Command::new(executable)
        .envs(values)
        .status();
}
