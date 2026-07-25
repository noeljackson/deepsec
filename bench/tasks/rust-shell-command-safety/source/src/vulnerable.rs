use std::process::Command;

fn execute_user_command(command: &str) {
    let _ = Command::new("sh")
        .arg("-c")
        .arg(command)
        .status();
}
