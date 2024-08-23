use std::process::Command;
use std::io::Write;
use std::fs::File;

fn main() {
    hashthis();
}

fn hashthis() {
    // Create and write to a temporary file
    let temp_file_path = "temp_file.txt";
    let mut file = File::create(temp_file_path).expect("Failed to create file");
    writeln!(file, "This is a2 test").expect("Failed to write to file");

    // Run the b3sum command
    let output = Command::new("b3sum")
        .arg(temp_file_path)
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

