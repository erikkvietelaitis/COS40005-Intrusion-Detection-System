use std::process::Command;
use std::fs;

fn main() {
    let fpath = "Cargo.toml";
    let koghfile = "kgh";
    hashthis(fpath, koghfile);
}

fn hashthis(fpath: &str, kogh: &str) {
    if !fs::metadata(fpath).is_ok() {
        eprintln!("File does not exist: {}", fpath);
        return;
    }

    // Run the b3sum command
    let output = Command::new("b3sum")
        .arg(fpath)
        .output()
        .expect("Failed to execute command");

    // Convert output to a string
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Print the result
    if output.status.success() {
        println!("Hash: {}", stdout.trim());
    } else {
        eprintln!("Error: {}", stderr);
    }
}

