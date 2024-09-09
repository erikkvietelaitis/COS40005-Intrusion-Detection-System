use crate::lara_core::*;                  // Importing core components ofthe LaraCore module
use rand::prelude::*;                    // Importing useful traits for random number generation and selection
use core_traits::AnalysisModule;        // Bringing in the AnalysisModule trait for implementation
use regex::Regex;                      // Importing Regex for pattern matching on strings
use crate::linux_bridge::sam;         // Importing functions from sam.rs

const MAX_RUNS: usize = 10;         // The number of runs we keep track of for averaging

// This is a struct to store system data for the current tick
#[derive(Debug, Copy, Clone)]
struct SystemData<'a> {
    file_name: &'a str,              // Name of the file being accessed
    command_executed: &'a str,      // Command that was executed
    cpu_usage: f32,                // Current CPU usage
    memory_usage: f32,            // Current memory usage
}

// This is the main structure for the AnomalyDetector module
pub struct AnomalyDetector<'a> {
    current_data: SystemData<'a>,               // Holds the data collected in the current tick
    history_of_filenames: Vec<&'a str>,        // Keeps a history of filenames accessed
    known_safe_commands: Vec<&'a str>,        // List of commands considered safe
    known_safe_files: Vec<&'a str>,          // List of files considered safe
    module_name: String,                    // Name of the module
    cpu_history: Vec<f32>,                 // Stores CPU usage for the last 10 runs
    memory_history: Vec<f32>,             // Stores memory usage for the last 10 runs
}

impl AnalysisModule for AnomalyDetector<'_> {
    // This function gathers system data
    fn get_data(&mut self) -> bool {
        // This will define lists of potential commands and files
        let commands: Vec<&str> = vec!["ls", "cat", "rm", "wget"];
        let files: Vec<&str> = vec!["/etc/passwd", "/var/log/syslog", "/home/user/.bashrc"];

        // Randomly select a command and a file to simulate system activity
        self.current_data = SystemData {
            file_name: *files.choose(&mut rand::thread_rng()).unwrap(),
            command_executed: *commands.choose(&mut rand::thread_rng()).unwrap(),
            cpu_usage: self.fetch_cpu_usage(),        // Fetch current CPU usage
            memory_usage: self.fetch_memory_usage(), // Fetch current memory usage
        };

        // Update CPU and memory history
        self.update_cpu_memory_history(self.current_data.cpu_usage, self.current_data.memory_usage);
        true // Tells us that the data collection was successful
    }

    // Function to gather predictable, testable data
    fn get_testing_data(&mut self) -> bool {
        todo!() // Placeholder for future implementation of testing data
    }

    // Function to analyse the gathered data and generate logs if anomalies are/were detected
    fn perform_analysis(&mut self) -> Vec<core_struts::Log> {
        let mut results: Vec<core_struts::Log> = Vec::new(); // Starts an empty vector to store logs

        // Define a pattern to detect suspicious commands
        let suspicious_pattern = Regex::new(r"rm").unwrap();

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

        // Perform CPU and memory anomaly checks
        if self.check_anomalous_cpu_usage(self.current_data.cpu_usage) {
            let msg = format!("⚠️ CPU usage anomaly detected: {:.2}% usage", self.current_data.cpu_usage);
            results.push(core_struts::Log::new(
                core_enums::LogType::Warning,
                self.module_name.clone(),
                msg,
            ));
        }

        if self.check_anomalous_memory_usage(self.current_data.memory_usage) {
            let msg = format!("⚠️ Memory usage anomaly detected: {:.2}% usage", self.current_data.memory_usage);
            results.push(core_struts::Log::new(
                core_enums::LogType::Warning,
                self.module_name.clone(),
                msg,
            ));
        }

        // Store the file name in the history for future reference
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

impl AnomalyDetector<'_> {
    // Fetches current CPU usage from the linux_bridge::sam module
    fn fetch_cpu_usage(&self) -> f32 {
        let cpu_data = sam::cpu_usage(); // Use the function from sam.rs
        // Parse the CPU usage string and return as f32 (placeholder for now -> add us + sy to get an approx. value??)
        // the TOP Command will generate output -- we can use that!!
        30.0 // Just an example value for now
    }

    // Fetches current memory usage from the linux_bridge::sam module
    fn fetch_memory_usage(&self) -> f32 {
        let memory_data = sam::memory_usage(); // Use the function from sam.rs
        // Parse the memory usage string and return as f32 (placeholder for now -> memory usage percentage = (used memory / total memory) * 100)
        50.0 // Just an example value for now
    }

    // Updates the CPU and memory history, keeping track of the last 10 runs
    fn update_cpu_memory_history(&mut self, cpu: f32, memory: f32) {
        if self.cpu_history.len() >= MAX_RUNS {
            self.cpu_history.remove(0); // Remove the oldest entry
        }
        if self.memory_history.len() >= MAX_RUNS {
            self.memory_history.remove(0); // Remove the oldest entry
        }
        self.cpu_history.push(cpu);      // Add the latest CPU usage
        self.memory_history.push(memory); // Add the latest memory usage
    }

    // Calculates the average of the CPU usage history
    fn average_cpu_usage(&self) -> f32 {
        let sum: f32 = self.cpu_history.iter().sum();
        sum / self.cpu_history.len() as f32
    }

    // Calculates the average of the memory usage history
    fn average_memory_usage(&self) -> f32 {
        let sum: f32 = self.memory_history.iter().sum();
        sum / self.memory_history.len() as f32
    }

    // Checks if the current CPU usage is more than 20% above the average
    fn check_anomalous_cpu_usage(&self, current_cpu: f32) -> bool {
        let avg_cpu = self.average_cpu_usage();
        current_cpu > avg_cpu * 1.2
    }

    // Checks if the current memory usage is more than 20% above the average
    fn check_anomalous_memory_usage(&self, current_memory: f32) -> bool {
        let avg_memory = self.average_memory_usage();
        current_memory > avg_memory * 1.2
    }
}

// This Implements the Default trait for AnomalyDetector to provide a default configuration
impl Default for AnomalyDetector<'_> {
    fn default() -> Self {
        Self {
            current_data: SystemData {
                file_name: "",
                command_executed: "",
                cpu_usage: 0.0,
                memory_usage: 0.0,
            }, // starts with empty data
            history_of_filenames: vec![],   // Start with an empty history
            known_safe_commands: vec!["ls", "cat", "cd", "echo"], // Define some default safe commands
            known_safe_files: vec!["/etc/passwd", "/var/log/syslog", "/home/user/.bashrc"], // Define some default safe files
            module_name: String::from("AnomalyDetectionModule"), // Set the module name
            cpu_history: vec![],           // Start with an empty CPU history
            memory_history: vec![],        // Start with an empty memory history
        }
    }
}

// Implements the Clone trait for AnomalyDetector to allow copying
impl Clone for AnomalyDetector<'_> {
    fn clone(&self) -> Self {
        Self {
            current_data: self.current_data,                     // Copy current data
            history_of_filenames: self.history_of_filenames.clone(), // Clone the history
            known_safe_commands: self.known_safe_commands.clone(),   // Clone the list of safe commands
            known_safe_files: self.known_safe_files.clone(),         // Clone the list of safe files
            module_name: self.module_name.clone(),               // Clone the module name
            cpu_history: self.cpu_history.clone(),               // Clone the CPU history
            memory_history: self.memory_history.clone(),         // Clone the memory history
        }
    }
}
