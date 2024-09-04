use crate::lara_core::*;               // Importing core components of the LaraCore module
use rand::prelude::*;                // Importing useful traits for random number generation and selection
use core_traits::AnalysisModule;     // Bringing in the AnalysisModule trait for implementation
use regex::Regex;                  // Importing Regex for pattern matching on strings

// This is a struct to store system data for the current tick
#[derive(Debug, Copy, Clone)]
struct SystemData<'a> {
    file_name: &'a str,         // Name of the file being accessed
    command_executed: &'a str, // Command that was executed
}

// This is the main structure for the AnomalyDetector module
pub struct AnomalyDetector<'a> {
    current_data: SystemData<'a>,        // Holds the data collected in the current tick
    history_of_filenames: Vec<&'a str>, // Keeps a history of filenames accessed
    known_safe_commands: Vec<&'a str>, // List of commands considered safe
    known_safe_files: Vec<&'a str>,   // List of files considered safe
    module_name: String,            // Name of the module
}

// This Implements the AnalysisModule trait for AnomalyDetector
impl AnalysisModule for AnomalyDetector<'_> {
    // This function gather's system data
    fn get_data(&mut self) -> bool {
        // This will define lists of potential commands and files
        let commands: Vec<&str> = vec!["ls", "cat", "rm", "wget"];
        let files: Vec<&str> = vec!["/etc/passwd", "/var/log/syslog", "/home/user/.bashrc"];

        // This Randomly selects a command and a file to simulate system activity
        self.current_data = SystemData {
            file_name: *files.choose(&mut rand::thread_rng()).unwrap(),
            command_executed: *commands.choose(&mut rand::thread_rng()).unwrap(),
        };
        true // Shows that data collection was successful
    }

    // Function to gather predictable, testable data
    fn get_testing_data(&mut self) -> bool {
        todo!() // Placeholder for future implementation of testing data
    }

    // This Function analysis the gathered data and generate logs if anomalies are detected
    fn perform_analysis(&mut self) -> Vec<core_struts::Log> {
        let mut results: Vec<core_struts::Log> = Vec::new();              // Initialise an empty vector to store logs

        let suspicious_pattern = Regex::new(r"rm").unwrap(); // Define a pattern to detect suspicious commands

        // Check if the executed command is not in the safe list or matches a suspicious pattern
        if !self.known_safe_commands.contains(&self.current_data.command_executed)
            || suspicious_pattern.is_match(self.current_data.command_executed)
        {
            // If an anomaly is detected, create a log message
            let msg = format!(
                "⚠️ Anomaly detected: Unrecognized or suspicious command executed: '{}'.",
                self.current_data.command_executed
            );
            // Add the log to the results
            results.push(core_struts::Log::new(
                core_enums::LogType::Serious,
                self.module_name.clone(),
                msg,
            ));
        }

        // Check if the accessed file is not in the safe list
        if !self.known_safe_files.contains(&self.current_data.file_name) {
            // If an anomaly is detected, create a log message
            let msg = format!(
                "🚨 Anomaly detected: Access to an unrecognized file: '{}'.",
                self.current_data.file_name
            );
            // Add the log to the results
            results.push(core_struts::Log::new(
                core_enums::LogType::Serious,
                self.module_name.clone(),
                msg,
            ));
        }

        // This stores the file name in the history for future reference
        self.history_of_filenames.push(self.current_data.file_name);
        results // Return the list of logs generated during analysis
    }

    // This function gets the name of the module
    fn get_name(&self) -> String {
        self.module_name.clone() // Return the name of the module
    }
    
    fn build_config_fields(&self) -> Vec<crate::ConfigField> {
        return Vec::new();
    }
    
    fn retrieve_config_data(&mut self, data: std::collections::HashMap<String, Vec<String>>) -> bool {
        return true;
    }
}

// This Implements the Default trait for AnomalyDetector to provide a default configuration
impl Default for AnomalyDetector<'_> {
    fn default() -> Self {
        Self {
            current_data: SystemData {
                file_name: "",
                command_executed: "",
            },                             // Initialise with empty data
            history_of_filenames: vec![], // Start with an empty history
            known_safe_commands: vec!["ls", "cat", "cd", "echo"],                            // Define some default safe commands
            known_safe_files: vec!["/etc/passwd", "/var/log/syslog", "/home/user/.bashrc"], // Define some default safe files
            module_name: String::from("AnomalyDetectionModule"),                           // Set the module name
        }
    }
}

// Implements the Clone trait for AnomalyDetector to allow copying
impl Clone for AnomalyDetector<'_> {
    fn clone(&self) -> Self {
        Self {
            current_data: self.current_data,                          // Copy current data
            history_of_filenames: self.history_of_filenames.clone(), // Clone the history
            known_safe_commands: self.known_safe_commands.clone(),  // Clone the list of safe commands
            known_safe_files: self.known_safe_files.clone(),       // Clone the list of safe files
            module_name: self.module_name.clone(),                // Clone the module name
        }
    }
}
