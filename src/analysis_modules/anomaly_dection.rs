use crate::lara_core::*;                  // Importing core components of the LaraCore module
use rand::prelude::*;                    // Importing useful traits for random number generation and selection
use core_traits::AnalysisModule;        // Bringing in the AnalysisModule trait for implementation
use regex::Regex;                      // Importing Regex for pattern matching on strings
use crate::linux_bridge::sam;         // Importing functions from sam.rs
use std::process::Command;           // For executing system commands
use chrono;

const MAX_RUNS: usize = 10;               // The number of runs we keep track of for averaging

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
#[derive(Debug, Clone)]
struct SystemData {
    file_name: String,                   // Name of the file being accessed
    command_executed: String,           // Command that was executed
    cpu_usage: f32,                    // Current CPU usage
    memory_usage: f32,                // Current memory usage
}

// This is the main structure for the AnomalyDetector module
pub struct AnomalyDetector {
    current_data: SystemData,                // Holds the data collected in the current tick
    history_of_filenames: Vec<String>,      // Keeps a history of filenames accessed
    known_safe_commands: Vec<String>,      // List of commands considered safe
    known_safe_files: Vec<String>,        // List of files considered safe
    module_name: String,                 // Name of the module
    cpu_history: Vec<f32>,              // Stores CPU usage for the last 10 runs
    memory_history: Vec<f32>,          // Stores memory usage for the last 10 runs
    previous_disks: Vec<DiskState>,   // Stores previous disk states for comparison
}

impl AnalysisModule for AnomalyDetector {
    // This function gathers system data
    fn get_data(&mut self) -> bool {
        // Fetch real running commands from the system using `ps`
        let command_executed = self.fetch_running_command();
        let files: Vec<&str> = vec!["/etc/passwd", "/var/log/syslog", "/home/user/.bashrc"];

        // Randomly select a file to simulate system activity
        self.current_data = SystemData {
            file_name: files.choose(&mut rand::thread_rng()).unwrap().to_string(),
            command_executed,
            cpu_usage: self.fetch_cpu_usage(),         // Fetch current CPU usage
            memory_usage: self.fetch_memory_usage(),  // Fetch current memory usage
        };

        // Update CPU and memory history
        self.update_cpu_memory_history(self.current_data.cpu_usage, self.current_data.memory_usage);
        true // Tells us that the data collection was successful
    }

    // Function to gather predictable data
    fn get_testing_data(&mut self) -> bool {
        todo!() 
    }

    // Function to analyse the gathered data and generate logs if anomalies are detected
    fn perform_analysis(&mut self) -> Vec<core_struts::Log> {
        let mut results: Vec<core_struts::Log> = Vec::new(); // Start an empty vector to store logs

        // Define a pattern to detect suspicious commands
        let suspicious_pattern = Regex::new(r"rm").unwrap();

        // Check if the executed command is not in the safe list or matches a suspicious pattern
        if !self.known_safe_commands.contains(&self.current_data.command_executed)
            || suspicious_pattern.is_match(&self.current_data.command_executed)
        {
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
        if !network_log.is_empty() {
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
        self.history_of_filenames.push(self.current_data.file_name.clone());
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

impl AnomalyDetector {
    // Fetch real commands using `ps` command
    fn fetch_running_command(&self) -> String {
        let output = Command::new("ps")
            .arg("aux")
            .output()
            .expect("Failed to execute `ps` command");
        let data = String::from_utf8_lossy(&output.stdout);

        // Extract command names (skip header, get commands from each line)
        let command_list: Vec<&str> = data.lines()
            .skip(1) // Skip the header row
            .map(|line| line.split_whitespace().nth(10).unwrap_or(""))
            .collect();

        // Pick a random running command
        let random_command = command_list.choose(&mut rand::thread_rng()).unwrap_or(&"");
        random_command.to_string()
    }

    // Fetch current CPU usage from `top` command
    fn fetch_cpu_usage(&self) -> f32 {
        let output = Command::new("top")
            .arg("-bn1")
            .output()
            .expect("Failed to execute command");
        let data = String::from_utf8_lossy(&output.stdout);

        // Process and extract the CPU usage information from the command output.
        let cpu_usage = data.lines()
            .filter(|line| line.contains("%Cpu(s)"))
            .next()
            .and_then(|line| {
                line.split_whitespace()
                    .nth(1)
                    .and_then(|usage| usage.trim_end_matches('%').parse::<f32>().ok())
            })
            .unwrap_or(0.0);

        cpu_usage
    }

    // Fetch current memory usage from `free` command
    fn fetch_memory_usage(&self) -> f32 {
        let output = Command::new("free")
            .arg("-m")
            .output()
            .expect("Failed to execute command");
        let data = String::from_utf8_lossy(&output.stdout);

        // Process and extract memory usage information from the free command
        let memory_usage = data.lines()
            .filter(|line| line.starts_with("Mem:"))
            .next()
            .and_then(|line| {
                let parts: Vec<&str> = line.split_whitespace().collect();
                let used_mem: f32 = parts[2].parse().unwrap_or(0.0);   // Used memory
                let total_mem: f32 = parts[1].parse().unwrap_or(1.0); // Total memory
                Some((used_mem / total_mem) * 100.0)
            })
            .unwrap_or(0.0);

        memory_usage
    }

    // Fetch disk usage from `df` command and filter `/dev` drives
    fn check_disk_changes_and_usage(&mut self) -> Vec<String> {
        let output = Command::new("df")
            .arg("-h")
            .output()
            .expect("Failed to execute df command");
        let data = String::from_utf8_lossy(&output.stdout);

        let mut logs: Vec<String> = Vec::new();
        let mut current_disks: Vec<DiskState> = Vec::new();

        for line in data.lines().skip(1) {  // Skipping the header row
            let disk_info: Vec<&str> = line.split_whitespace().collect();
            if disk_info.len() < 6 || !disk_info[0].starts_with("/dev") {
                continue; // We are only interested in /dev drives
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

    // Check for network packet drops
    fn check_network_packet_drops(&self) -> String {
        let output = Command::new("ifconfig")
            .output()
            .expect("Failed to execute ifconfig command");
        let data = String::from_utf8_lossy(&output.stdout);

        // Simplified network drop processing
        let packet_drop_data = data.lines()
            .filter(|line| line.contains("RX packets"))
            .collect::<Vec<&str>>();

        let drop_count: u32 = packet_drop_data.iter()
            .filter_map(|line| {
                line.split_whitespace()
                    .find(|word| word.starts_with("dropped"))
                    .and_then(|word| word.split(':').nth(1))
                    .and_then(|drops| drops.parse::<u32>().ok())
            })
            .sum();

        if drop_count > 0 {
            format!("{} dropped packets", drop_count)
        } else {
            String::new() // No dropped packets, return empty string to avoid logging
        }
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
impl Default for AnomalyDetector {
    fn default() -> Self {
        Self {
            current_data: SystemData {
                file_name: String::new(),
                command_executed: String::new(),
                cpu_usage: 0.0,
                memory_usage: 0.0,
            },
            history_of_filenames: vec![],
            known_safe_commands: vec!["ls".into(), "cat".into(), "cd".into(), "echo".into()],
            known_safe_files: vec!["/etc/passwd".into(), "/var/log/syslog".into(), "/home/user/.bashrc".into()],
            module_name: String::from("AnomalyDetectionModule"),
            cpu_history: vec![],
            memory_history: vec![],
            previous_disks: vec![],
        }
    }
}

// FORMATTING --

fn print_tick_info(tick_num: usize, cpu_usage: f32, memory_usage: f32) {
    println!("\n===== Tick #{} =====", tick_num);
    println!("-----------------------------------");
    println!("CPU Usage: {:.2}%", cpu_usage);
    println!("Memory Usage: {:.2}%", memory_usage);
    println!("");
}

fn print_module_success(module_name: &str) {
    println!("Module: '{}' - Successfully gathered data", module_name);
}

fn print_generated_logs(tick_num: usize, logs: Vec<core_struts::Log>) {
    if logs.is_empty() {
        println!("No anomalies detected during Tick({})", tick_num);
    } else {
        println!("\nGenerated Logs for Tick({}):", tick_num);
        println!("-----------------------------------");
        
        for log in logs {
            println!("{}", log.build_alert());
        }
    }
    println!("-----------------------------------\n");
}

fn print_tick_separator() {
    println!("-----------------------------------");
}
