use std::process::Command;

fn run_fixed_program() {
    let _ = Command::new("git")
        .arg("status")
        .arg("--short")
        .status();
}
