use crate::lara_core::*;
use core_traits::AnalysisModule;
use std::collections::HashMap;
use std::process::Command;
use std::path::Path;
use core_structs::*;
use dirhash::hash;
#[derive(Debug, Clone)]
struct CurrentData {
    new_hashes_files: HashMap<String, String>,
    new_hashes_folders: HashMap<String, String>,
}

pub struct FIM {
    // This is the data generated by gatherData in the current tick, it will be erased by the next tick
    current_data: CurrentData,
    // Everything else is persistent memory. The data you set in these will be remembered between ticks
    pub previous_hashes_files: HashMap<String, String>,
    pub previous_hashes_folders: HashMap<String, String>,
    module_name: String,
}

// Function to generate hash using the key
fn genhash(key: &str) -> (bool, String) {
    let output = match Command::new("/bin/Chromia/Data/b3sum")
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

fn genhash_folders(key: &str) -> (bool, String) {
    let dir_hash = hash(Path::new(key));
    
    // Calculate the hash of the directory
    match dir_hash {
        Ok(hash_value) => {
            println!("dirhash is {}",&hash_value);
            (true, hash_value.to_string())
        }
        Err(err) => {
            let errorm = err.to_string();
            println!("Error in dirhash: {}", errorm);
            (false, errorm)
        }
    }
    
    //println!("{}", stdout_str);

    
}

// Update section function
fn update_section_files(previous_hashes_files: &HashMap<String, String>, new_hashes_files: &mut HashMap<String, String>) -> bool {
    /*println!("previous_hashes:");
    for (key, hash) in previous_hashes.iter() {
        println!("Key: '{}', Hash: '{}'", key, hash);
    }*/

    let mut updated_section = HashMap::new();

    // Iterate over each file path in previous_hashes
    for (key, _) in previous_hashes_files {
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
    *new_hashes_files = updated_section;
    true
}

fn update_section_folders(previous_hashes_folders: &HashMap<String, String>, new_hashes_folders: &mut HashMap<String, String>) -> bool {
    /*println!("previous_hashes:");
    for (key, hash) in previous_hashes.iter() {
        println!("Key: '{}', Hash: '{}'", key, hash);
    }*/

    let mut updated_section_folders = HashMap::new();

    // Iterate over each file path in previous_hashes
    for (key, _) in previous_hashes_folders {
        if Path::new(key).exists() {
            println!("{} exists!", key);
        } else {
            println!("{} DOES NOT exist!", key);
            // Optionally handle files that existed before but are now missing
        }

        let (hash_success, hash) = genhash_folders(key);

        if hash_success {
            // Insert the key and hash into the updated HashMap
            updated_section_folders.insert(key.clone(), hash);
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
    *new_hashes_folders = updated_section_folders;
    true
}

impl AnalysisModule for FIM {
    fn get_data(&mut self) -> bool {
        // Update the section and handle the result
        if !update_section_files(&mut self.previous_hashes_files, &mut self.current_data.new_hashes_files) {
            return false; // Return false if update_section fails
        }
        if !update_section_folders(&mut self.previous_hashes_folders, &mut self.current_data.new_hashes_folders) {
            return false; // Return false if update_section fails
        }

        // Initialize new_hashes with the updated hashes
        //let new_hashes = self.previous_hashes.clone();

        // Update current_data with test data
        self.current_data = CurrentData {
            new_hashes_files: self.current_data.new_hashes_files.clone(),
            new_hashes_folders: self.current_data.new_hashes_folders.clone(),
        };

        true
    }

    fn get_testing_data(&mut self) -> bool {
        todo!()
    }

    fn perform_analysis(&mut self) -> Vec<core_structs::Log> {
        let mut results: Vec<core_structs::Log> = Vec::new();
    
        // Iterate over each filepath and hash in the new_hashes
        for (filepath, new_hash) in &self.current_data.new_hashes_files {
            match self.previous_hashes_files.get(filepath) {
                Some(previous_hash) => {
                    if new_hash != previous_hash {
                        // If hashes differ, create a log entry
                        let msg = format!(
                            "Object '{}' has been modified!",
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
                    eprintln!("Filepath '{}' not found in previous_hashes_files", filepath); // Debug print for missing filepaths
                    continue;
                }
            }
        }

        for (filepath, new_hash) in &self.current_data.new_hashes_folders {
            match self.previous_hashes_folders.get(filepath) {
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
                    eprintln!("Filepath '{}' not found in previous_hashes_files", filepath); // Debug print for missing filepaths
                    continue;
                }
            }
        }
    
        // Update previous_hashes to be the same as new_hashes
        self.previous_hashes_files = self.current_data.new_hashes_files.clone();
        self.previous_hashes_folders = self.current_data.new_hashes_folders.clone();
    
        results
    }

    fn get_name(&self) -> String {
        self.module_name.clone()
    }
    fn build_config_fields(&self) -> Vec<crate::ConfigField> {
        let fields:Vec<ConfigField> = vec![
            ConfigField::new("files".to_owned(),"Files to be monitored for integrity violations, must be an absolute path".to_owned(),core_enums::ConfigFieldType::Integer,vec!["/home/ids/Documents/GitHub/COS40005-Intrusion-Detection-System/config.ini".to_owned()], true),
            ConfigField::new("folders".to_owned(),"Files to be monitored for integrity violations, must be an absolute path".to_owned(),core_enums::ConfigFieldType::Integer,vec!["/home/ids/Documents/GitHub/COS40005-Intrusion-Detection-System/src".to_owned()], true)
        ];
        
        return fields;
    }
    fn retrieve_config_data(&mut self, data: HashMap<String,Vec<String>>) -> bool{
        let mut files = HashMap::new();
        let mut folders: HashMap<String, String> = HashMap::new();
        //println!("{}",self.module_name);

        for (field, vals) in data.iter() {
            if field == "files" {
                for val in vals {
                    files.insert(val.clone(), String::new()); // Insert file paths with empty hashes initially
                }
            }
            if field == "folders" {
                for val in vals {
                    folders.insert(val.clone(), String::new()); // Insert file paths with empty hashes initially
                }
            }
        }
        self.previous_hashes_files = files;
        self.previous_hashes_folders = folders;
        

        println!("previous_hashes_files:");
        for (key, hash) in self.previous_hashes_files.iter() {
            println!("Key: '{}', Hash: '{}'", key, hash);
        }
        println!("previous_hashes_folders:");
        for (key, hash) in self.previous_hashes_folders.iter() {
            println!("Key: '{}', Hash: '{}'", key, hash);
        }

        return true;
    }
}

impl Default for FIM {
    fn default() -> Self {

        Self {
            previous_hashes_files: HashMap::new(),
            previous_hashes_folders: HashMap::new(),
            module_name: String::from("FIM"),
            current_data: CurrentData {
                new_hashes_files: HashMap::new(),
                new_hashes_folders: HashMap::new(),
            },
        }
    }
}

impl Clone for FIM {
    fn clone(&self) -> Self {
        Self {
            current_data: self.current_data.clone(),
            previous_hashes_files: self.previous_hashes_files.clone(),
            previous_hashes_folders: self.previous_hashes_folders.clone(),
            module_name: self.module_name.clone(),
        }
    }
}
