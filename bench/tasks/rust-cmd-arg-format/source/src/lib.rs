use std::process::Command;

pub fn run_vulnerable_argv() {
    let args: Vec<String> = std::env::args().collect();
    let name = &args[1];
    let _ = Command::new("sh").arg(format!("-c \"echo {}\"", name)).status();
}

pub fn run_safe(value: &str) {
    let _ = Command::new("echo").arg(value).status();
}
