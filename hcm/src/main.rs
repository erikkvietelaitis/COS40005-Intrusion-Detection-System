use std::process::Command;
use std::fs;
use std::fs::File;
use csv::ReaderBuilder;
use std::path::Path;

fn main() {
    let fpath = "Cargo.toml"; // Path for checking existence
    let koghfile = "kgh";     // Path to the CSV file
    let debug = 0;           // Set to 1 to enable debug output, 0 to disable

    if debug == 1 {
        println!("Starting the program...");
    }

    hashthis(fpath, koghfile, debug);
}

fn hashthis(fpath: &str, kogh: &str, debug: u8) {
    // Check if the file exists
    if !fs::metadata(fpath).is_ok() {
        eprintln!("File does not exist: {}", fpath);
        return;
    }
    if debug == 1 {
        println!("File {} exists. Proceeding...", fpath);
    }

    // Open the CSV file
    let file = match File::open(kogh) {
        Ok(file) => file,
        Err(err) => {
            eprintln!("Error opening file {}: {}", kogh, err);
            return;
        }
    };
    if debug == 1 {
        println!("Opened CSV file: {}", kogh);
    }

    // Create a CSV reader with headers
    let mut rdr = ReaderBuilder::new().has_headers(true).from_reader(file);
    if debug == 1 {
        println!("CSV reader created.");
    }

    let mut record_count = 0;

    // Iterate over records
    for (i, result) in rdr.records().enumerate() {
        let record_number = i + 1; // Record numbers are 1-based for user-friendly output

        if debug == 1 {
            println!("Attempting to read record {}", record_number);
        }

        let record = match result {
            Ok(record) => {
                if debug == 1 {
                    println!("Read record {}: {:?}", record_number, record);
                }
                record_count += 1;
                record
            },
            Err(err) => {
                eprintln!("Error reading record {}: {}", record_number, err);
                continue;  // Skip this record and continue with the next
            }
        };

        // Access columns by name and trim quotes if present
        let column1 = record.get(0).unwrap_or(&"").trim_matches('"');
        let column2 = record.get(1).unwrap_or(&"");

        // Check if the file exists before running the command
        if !Path::new(column1).exists() {
            eprintln!("File does not exist: {}", column1);
            continue;
        }

        if debug == 1 {
            println!("Column 1 (file path): {}", column1);
            println!("Expected Hash (Column 2): {}", column2);
        }

        // Run the b3sum command
        if debug == 1 {
            println!("Running command: b3sum {}", column1);
        }
        let output = match Command::new("b3sum")
            .arg(column1)
            .output() {
            Ok(output) => output,
            Err(err) => {
                eprintln!("Failed to execute command for record {}: {}", record_number, err);
                continue;  // Skip this record and continue with the next
            }
        };

        // Convert output to a string
        let stdout_str = String::from_utf8_lossy(&output.stdout);
        let stderr_str = String::from_utf8_lossy(&output.stderr);

        // Print command output and errors
        if debug == 1 {
            if !stderr_str.is_empty() {
                eprintln!("Error output for record {}: {}", record_number, stderr_str);
            }
            if !stdout_str.is_empty() {
                println!("Command output for record {}: {}", record_number, stdout_str);
            } else {
                eprintln!("No output from command for record {}.", record_number);
            }
        }

        // Check if the command was successful
        if output.status.success() {
            // Split the output string by spaces
            let parts: Vec<&str> = stdout_str.split_whitespace().collect();
            
            // Assuming the hash is always the first part
            if !parts.is_empty() {
                let hash = parts[0];
                if debug == 1 {
                    println!("Extracted hash for record {}: {}", record_number, hash);
                }
                if hash == column2 {
                    println!("Hashes match for file {}!", column1);
                } else {
                    if debug == 1 {
                        println!("Hashes do not match for file {}.", column1);
                    }
                }
            } else {
                if debug == 1 {
                    println!("Unexpected output format for record {}.", record_number);
                }
            }
            
            if debug == 1 {
                println!("Hash for record {}: {}", record_number, stdout_str.trim());
            }
        } else {
            if debug == 1 {
                eprintln!("Command failed with status for record {}: {:?}", record_number, output.status);
            }
        }
        
        if debug == 1 {
            println!("Finished processing record {}.", record_number);
        }
    }

    if debug == 1 {
        println!("Finished processing all records. Total records processed: {}", record_count);
    }
}
