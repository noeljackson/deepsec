use std::{collections::BTreeMap, process::Command};

fn run_profile(executable: &str, values: BTreeMap<String, String>) {
    // Remove wrapper credentials before giving the child profile values.
    let _ = Command::new(executable)
        .env_remove("BROKER_TOKEN")
        .env_remove("BROKER_BASIC_USER")
        .env_remove("BROKER_BASIC_PASSWORD")
        .envs(values)
        .status();
}
