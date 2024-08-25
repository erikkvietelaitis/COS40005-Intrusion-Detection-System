use std::process::Command;
use std::fs;
use csv::Reader;

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
    let file = File::open(kogh)?;
    
    // Create a CSV reader
    let mut rdr = Reader::from_reader(file);

    // Iterate over records
    for result in rdr.records() {
        let record = result?;
        // Assuming the CSV has exactly two columns
        let column1 = &record[0];
        let column2 = &record[1];

        let output = Command::new("b3sum")
        .arg(column1)
        .output()
        .expect("Failed to execute command");

        // Convert output to a string
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        let input = stdout;
    
        // Split the input string by spaces
        let parts: Vec<&str> = input.split_whitespace().collect();
        
        // Assuming the hash is always the second part
        if parts.len() >= 2 {
            let hash = parts[1];
            println!("Extracted hash: {}", hash);
        } else {
            println!("Unexpected input format");
        }
        if (hash.eq(column2)) {
            println!("Hashes match!");
        }

        // Print the result
        if output.status.success() {
            println!("Hash: {}", stdout.trim());
        } else {
            eprintln!("Error: {}", stderr);
        }
        
        println!("Column 1: {}, Column 2: {}", column1, column2);
    }

    // Run the b3sum command
    
}

