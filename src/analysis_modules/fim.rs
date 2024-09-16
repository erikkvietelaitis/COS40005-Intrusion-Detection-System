use crate::lara_core::*;
use core_traits::AnalysisModule;
use std::collections::HashMap;
use std::process::Command;
use std::path::Path;
use core_structs::*;
#[derive(Debug, Clone)]
struct CurrentData {
    new_hashes: HashMap<String, String>,
}

pub struct FIM {
    // This is the data generated by gatherData in the current tick, it will be erased by the next tick
    current_data: CurrentData,
    // Everything else is persistent memory. The data you set in these will be remembered between ticks
    pub previous_hashes: HashMap<String, String>,
    module_name: String,
}

// Function to generate hash using the key
fn genhash(key: &str) -> (bool, String) {
    let output = match Command::new("sudo")
        .arg("b3sum")
        .arg(key)
        .arg("--no-names")
        .output() {
        
        Ok(output) => output,
        Err(err) => {
            eprintln!("Failed to execute command for key '{}': {}", key, err);
            return (false, String::new());
        }
    };
    // Convert output to string
    let stdout_str = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr_str = String::from_utf8_lossy(&output.stderr).into_owned();
    
    //println!("{}", stdout_str);

    if !stderr_str.is_empty() {
        eprintln!("stderr for key '{}': {}", key, stderr_str);
    }

    (true, stdout_str)
}

// Update section function
fn update_section(previous_hashes: &HashMap<String, String>, new_hashes: &mut HashMap<String, String>) -> bool {
    /*println!("previous_hashes:");
    for (key, hash) in previous_hashes.iter() {
        println!("Key: '{}', Hash: '{}'", key, hash);
    }*/

    let mut updated_section = HashMap::new();

    // Iterate over each file path in previous_hashes
    for (key, _) in previous_hashes {
        if Path::new(key).exists() {
            println!("{} exists!", key);
        } else {
            println!("{} DOES NOT exist!", key);
            // Optionally handle files that existed before but are now missing
        }

        let (hash_success, hash) = genhash(key);

        if hash_success {
            // Insert the key and hash into the updated HashMap
            updated_section.insert(key.clone(), hash);
        } else {
            eprintln!("Failed to generate hash for key '{}'", key);
            return false;
        }
    }

    // Print the contents of updated_section
    /*println!("Updated section contents:");
    for (key, hash) in &updated_section {
        println!("Key: '{}', Hash: '{}'", key, hash);
    }*/

    // Update new_hashes with the new hashes
    *new_hashes = updated_section;
    true
}

impl AnalysisModule for FIM {
    fn get_data(&mut self) -> bool {
        // Update the section and handle the result
        if !update_section(&mut self.previous_hashes, &mut self.current_data.new_hashes) {
            return false; // Return false if update_section fails
        }

        // Initialize new_hashes with the updated hashes
        //let new_hashes = self.previous_hashes.clone();

        // Update current_data with test data
        self.current_data = CurrentData {
            new_hashes: self.current_data.new_hashes.clone(),
        };

        true
    }

    fn get_testing_data(&mut self) -> bool {
        todo!()
    }

    fn perform_analysis(&mut self) -> Vec<core_structs::Log> {
        let mut results: Vec<core_structs::Log> = Vec::new();
    
        // Iterate over each filepath and hash in the new_hashes
        for (filepath, new_hash) in &self.current_data.new_hashes {
            match self.previous_hashes.get(filepath) {
                Some(previous_hash) => {
                    if new_hash != previous_hash {
                        // If hashes differ, create a log entry
                        let msg = format!(
                            "File '{}' has been modified!",
                            filepath
                        );
                        eprintln!("Log: {}", msg); // Debug print for logs
                        results.push(crate::Log::new(
                            core_enums::LogType::Serious,
                            self.module_name.clone(),
                            msg,
                        ));
                    }
                }
                None => {
                    eprintln!("Filepath '{}' not found in previous_hashes", filepath); // Debug print for missing filepaths
                    continue;
                }
            }
        }
    
        // Update previous_hashes to be the same as new_hashes
        self.previous_hashes = self.current_data.new_hashes.clone();
    
        results
    }

    fn get_name(&self) -> String {
        self.module_name.clone()
    }
    fn build_config_fields(&self) -> Vec<crate::ConfigField> {
        let fields:Vec<ConfigField> = vec![
            ConfigField::new("files".to_owned(),"Files to be monitored for integrity violations, must be an absolute path".to_owned(),core_enums::ConfigFieldType::Integer,vec!["/home/ids/Documents/GitHub/COS40005-Intrusion-Detection-System/config.ini".to_owned()], true)
        ];
        
        return fields;
    }
    fn retrieve_config_data(&mut self, data: HashMap<String,Vec<String>>) -> bool{
        let mut files = HashMap::new();
        //println!("{}",self.module_name);

        for (field, vals) in data.into_iter() {
            if field == "files" {
                for val in vals {
                    files.insert(val, String::new()); // Insert file paths with empty hashes initially
                }
            }
        }
        self.previous_hashes = files;

        println!("previous_hashes:");
        for (key, hash) in self.previous_hashes.iter() {
            println!("Key: '{}', Hash: '{}'", key, hash);
        }

        return true;
    }
}

impl Default for FIM {
    fn default() -> Self {

        Self {
            previous_hashes: HashMap::new(),
            module_name: String::from("FIM"),
            current_data: CurrentData {
                new_hashes: HashMap::new(),
            },
        }
    }
}

impl Clone for FIM {
    fn clone(&self) -> Self {
        Self {
            current_data: self.current_data.clone(),
            previous_hashes: self.previous_hashes.clone(),
            module_name: self.module_name.clone(),
        }
    }
}