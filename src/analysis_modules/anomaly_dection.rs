use crate::lara_core::*;                  // Importing core components of the LaraCore module
use rand::prelude::*;                    // Importing useful traits for random number generation and selection
use core_traits::AnalysisModule;        // Bringing in the AnalysisModule trait for implementation
use regex::Regex;                      // Importing Regex for pattern matching on strings
use crate::linux_bridge::sam;         // Importing functions from sam.rs
use std::process::Command;

const MAX_RUNS: usize = 10;         // The number of runs we keep track of for averaging

// Struct to store disk state
#[derive(Clone, Debug)]
struct DiskState {
    filesystem: String,
    size: String,
    used: String,
    avail: String,
    use_percent: f32,
}

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
    previous_disks: Vec<DiskState>,      // Stores previous disk states for comparison
}

impl AnalysisModule for AnomalyDetector<'_> {
    // This function gathers system data
    fn get_data(&mut self) -> bool {
        // Define lists of potential commands and files
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

    // Function to analyse the gathered data and generate logs if anomalies are detected
    fn perform_analysis(&mut self) -> Vec<core_struts::Log> {
        let mut results: Vec<core_struts::Log> = Vec::new(); // Start an empty vector to store logs

        // Define a pattern to detect suspicious commands
        let suspicious_pattern = Regex::new(r"rm").unwrap();

        // Check if the executed command is not in the safe list or matches a suspicious pattern
        if !self.known_safe_commands.contains(&self.current_data.command_executed)
            || suspicious_pattern.is_match(self.current_data.command_executed)
        {
            // If an anomaly is detected, create a log message
            let msg = format!(
                "[{}]=[{}]=[Serious]: A suspicious command '{}' was executed.",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                self.module_name,
                self.current_data.command_executed
            );
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
                "[{}]=[{}]=[Serious]: An unrecognized file '{}' was accessed.",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                self.module_name,
                self.current_data.file_name
            );
            results.push(core_struts::Log::new(
                core_enums::LogType::Serious,
                self.module_name.clone(),
                msg,
            ));
        }

        // Check for CPU and memory usage anomalies
        if self.check_anomalous_cpu_usage(self.current_data.cpu_usage) {
            let msg = format!(
                "[{}]=[{}]=[Warning]: CPU usage is at {:.2}% which is higher than the expected average.",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                self.module_name,
                self.current_data.cpu_usage
            );
            results.push(core_struts::Log::new(
                core_enums::LogType::Warning,
                self.module_name.clone(),
                msg,
            ));
        }

        if self.check_anomalous_memory_usage(self.current_data.memory_usage) {
            let msg = format!(
                "[{}]=[{}]=[Warning]: Memory usage is at {:.2}% which is higher than the expected average.",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                self.module_name,
                self.current_data.memory_usage
            );
            results.push(core_struts::Log::new(
                core_enums::LogType::Warning,
                self.module_name.clone(),
                msg,
            ));
        }

        // Call network packet drop detection and logging
        let network_log = self.check_network_packet_drops();
        if !network_log.contains("No dropped packets") {
            let msg = format!(
                "[{}]=[{}]=[Warning]: Network issues detected with packet drops. {}",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                self.module_name,
                network_log
            );
            results.push(core_struts::Log::new(
                core_enums::LogType::Warning,
                self.module_name.clone(),
                msg,
            ));
        }

        // Check disk changes and abnormal usage
        let disk_logs = self.check_disk_changes_and_usage();
        for disk_log in disk_logs {
            let msg = format!(
                "[{}]=[{}]=[Warning]: {}",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                self.module_name,
                disk_log
            );
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

    fn get_name(&self) -> String {
        self.module_name.clone() // Return the name of the module
    }

    fn build_config_fields(&self) -> Vec<crate::ConfigField> {
        Vec::new()
    }

    fn retrieve_config_data(&mut self, _data: std::collections::HashMap<String, Vec<String>>) -> bool {
        true
    }
}

impl AnomalyDetector<'_> {
    // Fetch current CPU usage from sam.rs
    fn fetch_cpu_usage(&self) -> f32 {
        let output = Command::new("top")
            .arg("-b")
            .arg("-n")
            .arg("1")
            .output()
            .expect("Failed to fetch CPU usage");

        let result = String::from_utf8_lossy(&output.stdout);
        let cpu_line = result.lines().find(|line| line.contains("Cpu(s)")).unwrap_or("Cpu(s): 0.0 us");

        let usage_data: Vec<&str> = cpu_line.split_whitespace().collect();
        let cpu_usage: f32 = usage_data.get(1).unwrap_or(&"0.0").parse().unwrap_or(0.0);

        cpu_usage
    }

    // Fetch current memory usage from sam.rs
    fn fetch_memory_usage(&self) -> f32 {
        let output = Command::new("free")
            .arg("-m")
            .output()
            .expect("Failed to fetch memory usage");

        let result = String::from_utf8_lossy(&output.stdout);
        let memory_line = result.lines().nth(1).unwrap_or("");

        let memory_data: Vec<&str> = memory_line.split_whitespace().collect();
        let used_memory: f32 = memory_data.get(2).unwrap_or(&"0.0").parse().unwrap_or(0.0);
        let total_memory: f32 = memory_data.get(1).unwrap_or(&"1.0").parse().unwrap_or(1.0);

        (used_memory / total_memory) * 100.0
    }

    // Check for network packet drops
    fn check_network_packet_drops(&self) -> String {
        let output = Command::new("ip")
            .arg("-s")
            .arg("link")
            .output()
            .expect("Failed to fetch network data");

        let result = String::from_utf8_lossy(&output.stdout);
        let dropped_packets: u32 = result
            .lines()
            .filter(|line| line.contains("RX"))
            .map(|line| {
                let data: Vec<&str> = line.split_whitespace().collect();
                data.get(3).unwrap_or(&"0").parse().unwrap_or(0)
            })
            .sum();

        let avg_dropped_packets = dropped_packets as f32 / MAX_RUNS as f32;

        format!("{} dropped packets, average: {:.2}", dropped_packets, avg_dropped_packets)
    }

    // Check for disk changes and abnormal usage
    fn check_disk_changes_and_usage(&mut self) -> Vec<String> {
        let output = sam::disk_usage(); // Get disk usage data from sam.rs
        let mut logs: Vec<String> = Vec::new();

        let mut current_disks: Vec<DiskState> = Vec::new();
        for line in output.lines().skip(1) {  // Skip the header row
            let disk_info: Vec<&str> = line.split_whitespace().collect();
            if disk_info.len() < 6 || !disk_info[0].starts_with("/dev") {
                continue; // Ignore invalid rows or non-dev drives
            }

            let use_percent = disk_info[4].trim_end_matches('%').parse::<f32>().unwrap_or(0.0);
            let disk = DiskState {
                filesystem: disk_info[0].to_string(),
                size: disk_info[1].to_string(),
                used: disk_info[2].to_string(),
                avail: disk_info[3].to_string(),
                use_percent,
            };
            current_disks.push(disk.clone());

            // Compare with previous disk states to detect new or missing disks
            let found_in_previous = self.previous_disks.iter().any(|d| d.filesystem == disk.filesystem);
            if !found_in_previous {
                logs.push(format!("A new disk was detected: {}", disk.filesystem));
            }

            // Check for abnormal usage (>20% increase in use)
            if let Some(prev_disk) = self.previous_disks.iter().find(|d| d.filesystem == disk.filesystem) {
                if disk.use_percent > prev_disk.use_percent * 1.2 {
                    logs.push(format!(
                        "An abnormal increase in disk usage was detected on '{}'. Usage increased by more than 20%.",
                        disk.filesystem
                    ));
                }
            }
        }

        // Detect if any disk is missing
        for prev_disk in self.previous_disks.iter() {
            if !current_disks.iter().any(|d| d.filesystem == prev_disk.filesystem) {
                logs.push(format!("Disk '{}' was removed.", prev_disk.filesystem));
            }
        }

        self.previous_disks = current_disks; // Update previous disk state
        logs
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

    fn average_cpu_usage(&self) -> f32 {
        let sum: f32 = self.cpu_history.iter().sum();
        sum / self.cpu_history.len() as f32
    }

    fn average_memory_usage(&self) -> f32 {
        let sum: f32 = self.memory_history.iter().sum();
        sum / self.memory_history.len() as f32
    }

    fn check_anomalous_cpu_usage(&self, current_cpu: f32) -> bool {
        current_cpu > self.average_cpu_usage() * 1.2
    }

    fn check_anomalous_memory_usage(&self, current_memory: f32) -> bool {
        current_memory > self.average_memory_usage() * 1.2
    }
}

// Implement Default for AnomalyDetector
impl Default for AnomalyDetector<'_> {
    fn default() -> Self {
        Self {
            current_data: SystemData {
                file_name: "",
                command_executed: "",
                cpu_usage: 0.0,
                memory_usage: 0.0,
            }, 
            history_of_filenames: vec![],   
            known_safe_commands: vec!["ls", "cat", "cd", "echo"], 
            known_safe_files: vec!["/etc/passwd", "/var/log/syslog", "/home/user/.bashrc"], 
            module_name: String::from("AnomalyDetectionModule"),
            cpu_history: vec![],           
            memory_history: vec![],        
            previous_disks: vec![],        // Initialize previous disk state as empty
        }
    }
}

// Implements the Clone trait for AnomalyDetector
impl Clone for AnomalyDetector<'_> {
    fn clone(&self) -> Self {
        Self {
            current_data: self.current_data,
            history_of_filenames: self.history_of_filenames.clone(),
            known_safe_commands: self.known_safe_commands.clone(),
            known_safe_files: self.known_safe_files.clone(),
            module_name: self.module_name.clone(),
            cpu_history: self.cpu_history.clone(),
            memory_history: self.memory_history.clone(),
            previous_disks: self.previous_disks.clone(),
        }
    }
}
