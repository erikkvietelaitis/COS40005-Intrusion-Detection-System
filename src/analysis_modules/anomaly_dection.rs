// Necessary imports
use crate::lara_core::*;                            // Import core components
use core_traits::AnalysisModule;                   // Trait for implementation
use regex::Regex;                                 // For pattern matching
use std::process::Command;                       // For executing system commands
use std::collections::{HashMap, HashSet};       // For configuration data and seen commands
use crate::ConfigField;                        // For configuration fields
use core_enums::*;                            // For config field types and log types
use users::{self, os::unix::UserExt};        // For getting user information
use std::process;                           // For getting current process ID
use std::time::{SystemTime, UNIX_EPOCH};   // For timestamps
use notify::{RecommendedWatcher, RecursiveMode, Watcher, EventKind, Event};
use std::sync::{Arc, Mutex};
use std::sync::mpsc::channel;
use std::path::PathBuf;
use dirs;
use chrono;                                 // For timestamp formatting

const MAX_RUNS: usize = 10;                 // Number of runs to keep track of for averaging

// Struct to store disk state
#[derive(Clone, Debug)]
struct DiskState {
    filesystem: String,
    size: String,
    used: String,
    avail: String,
    use_percent: f32,
}

// Struct to store system data for the current tick
#[derive(Debug, Clone)]
struct SystemData {
    file_name: String,              // Name of the file being accessed
    command_executed: String,      // Command that was executed
    user: String,                 // User who ran the command
    cpu_usage: f32,              // Current CPU usage
    memory_usage: f32,          // Current memory usage
}

// Main structure for the AnomalyDetector module
pub struct AnomalyDetector {
    current_data: SystemData,                     // Data collected in the current tick
    history_of_filenames: Vec<String>,           // History of filenames accessed
    known_safe_commands: Vec<String>,           // List of commands considered safe
    known_safe_files: Vec<String>,             // List of files considered safe
    known_unsafe_commands: Vec<String>,       // List of commands considered unsafe
    known_unsafe_files: Vec<String>,         // List of files considered unsafe
    suspicious_patterns: Vec<String>,       // Regex patterns for suspicious commands
    module_name: String,                   // Name of the module
    cpu_history: Vec<f32>,                // CPU usage for the last 10 runs
    memory_history: Vec<f32>,            // Memory usage for the last 10 runs
    previous_disks: Vec<DiskState>,     // Previous disk states for comparison
    seen_commands: HashSet<String>,    // Commands already seen to prevent duplicates
    last_command_timestamp: u64,      // Timestamp of the last command processed
    file_events: Arc<Mutex<Vec<String>>>,   // Shared file events between threads
}

impl AnalysisModule for AnomalyDetector {
    // Function to gather system data
    fn get_data(&mut self) -> bool {
        // Fetch recent commands from the system
        if let Some((user, command_executed)) = self.fetch_recent_command() {
            self.current_data.command_executed = command_executed;
            self.current_data.user = user;
        } else {
        // If no recent command, clear the command data
            self.current_data.command_executed.clear();
            self.current_data.user.clear();
        }

        // Process collected file events
        if let Ok(mut events) = self.file_events.lock() {
            if let Some(file_name) = events.pop() {
                self.current_data.file_name = file_name;
            } else {
                self.current_data.file_name.clear();
            }
        }

        // Fetch current CPU and memory usage
        self.current_data.cpu_usage = self.fetch_cpu_usage();
        self.current_data.memory_usage = self.fetch_memory_usage();

        // Update CPU and memory history
        self.update_cpu_memory_history(self.current_data.cpu_usage, self.current_data.memory_usage);

        true // Data collection was successful
    }

    // Function to gather predictable data (not implemented)
    fn get_testing_data(&mut self) -> bool {
        // Implement if you need to simulate data for testing
        false
    }

    // Function to analyze the gathered data and generate logs if anomalies are detected
    fn perform_analysis(&mut self) -> Vec<core_structs::Log> {
        let mut results: Vec<core_structs::Log> = Vec::new();

        // Extract command name
        let command_executed = self.current_data.command_executed.clone();
        let command_name = command_executed
            .split('/')
            .last()
            .unwrap_or("")
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_string();

        // Compile suspicious command patterns
        let suspicious_patterns = self.suspicious_command_patterns();

        // Check if the executed command is suspicious
        let is_suspicious = suspicious_patterns.iter().any(|regex| regex.is_match(&command_name))
            || self.known_unsafe_commands.contains(&command_name);

        if !command_name.is_empty() && (!self.known_safe_commands.contains(&command_name) || is_suspicious) {
            let msg = format!(
                "[{}]=[{}]=[Serious]: User '{}' executed a suspicious or unrecognized command '{}'.",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                self.module_name,
                self.current_data.user,
                command_executed
            );
            results.push(core_structs::Log::new(
                LogType::Serious,
                self.module_name.clone(),
                msg,
            ));
        }

        // Check if the accessed file is not in the safe list or is in the unsafe list
        if !self.current_data.file_name.is_empty()
            && (!self.known_safe_files.contains(&self.current_data.file_name)
                || self.known_unsafe_files.contains(&self.current_data.file_name))
        {
            let msg = format!(
                "[{}]=[{}]=[Serious]: An unrecognized or unsafe file '{}' was accessed.",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                self.module_name,
                self.current_data.file_name
            );
            results.push(core_structs::Log::new(
                LogType::Serious,
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
            results.push(core_structs::Log::new(
                LogType::Warning,
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
            results.push(core_structs::Log::new(
                LogType::Warning,
                self.module_name.clone(),
                msg,
            ));
        }

        // Check network packet drops and log if necessary
        let network_log = self.check_network_packet_drops();
        if !network_log.is_empty() {
            let msg = format!(
                "[{}]=[{}]=[Warning]: Network issues detected with packet drops. {}",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                self.module_name,
                network_log
            );
            results.push(core_structs::Log::new(
                LogType::Warning,
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
            results.push(core_structs::Log::new(
                LogType::Warning,
                self.module_name.clone(),
                msg,
            ));
        }

        // Store the file name in the history for future reference
        if !self.current_data.file_name.is_empty() {
            self.history_of_filenames.push(self.current_data.file_name.clone());
        }
        results // Return the list of logs generated during analysis
    }

    // Return the name of the module
    fn get_name(&self) -> String {
        self.module_name.clone()
    }

    // Define configurable fields for the module
    fn build_config_fields(&self) -> Vec<ConfigField> {
        vec![
            ConfigField::new(
                "KnownSafeCommands".to_owned(),
                "List of commands considered safe".to_owned(),
                ConfigFieldType::String,
                self.known_safe_commands.clone(),
                true, // Allows multiple values
            ),
            ConfigField::new(
                "KnownSafeFiles".to_owned(),
                "List of files considered safe".to_owned(),
                ConfigFieldType::String,
                self.known_safe_files.clone(),
                true, // Allows multiple values
            ),
            ConfigField::new(
                "KnownUnsafeCommands".to_owned(),
                "List of commands considered unsafe".to_owned(),
                ConfigFieldType::String,
                self.known_unsafe_commands.clone(),
                true, // Allows multiple values
            ),
            ConfigField::new(
                "KnownUnsafeFiles".to_owned(),
                "List of files considered unsafe".to_owned(),
                ConfigFieldType::String,
                self.known_unsafe_files.clone(),
                true, // Allows multiple values
            ),
            ConfigField::new(
                "SuspiciousCommandPatterns".to_owned(),
                "Regex patterns for suspicious commands".to_owned(),
                ConfigFieldType::String,
                self.suspicious_patterns.clone(),
                true, // Allows multiple values
            ),
        ]
    }

    // Retrieve user-provided configuration data with validation
    fn retrieve_config_data(&mut self, data: HashMap<String, Vec<String>>) -> bool {
        let mut success = true;
        for (field, vals) in data {
            match field.as_str() {
                "KnownSafeCommands" => {
                    if vals.iter().all(|cmd| !cmd.trim().is_empty()) {
                        self.known_safe_commands = vals;
                    } else {
                        eprintln!("Invalid command in KnownSafeCommands.");
                        success = false;
                    }
                }
                "KnownSafeFiles" => {
                    if vals.iter().all(|file| !file.trim().is_empty()) {
                        self.known_safe_files = vals;
                    } else {
                        eprintln!("Invalid file in KnownSafeFiles.");
                        success = false;
                    }
                }
                "KnownUnsafeCommands" => {
                    if vals.iter().all(|cmd| !cmd.trim().is_empty()) {
                        self.known_unsafe_commands = vals;
                    } else {
                        eprintln!("Invalid command in KnownUnsafeCommands.");
                        success = false;
                    }
                }
                "KnownUnsafeFiles" => {
                    if vals.iter().all(|file| !file.trim().is_empty()) {
                        self.known_unsafe_files = vals;
                    } else {
                        eprintln!("Invalid file in KnownUnsafeFiles.");
                        success = false;
                    }
                }
                "SuspiciousCommandPatterns" => {
                    let mut valid_patterns = Vec::new();
                    for pattern in vals {
                        match Regex::new(&pattern) {
                            Ok(_) => valid_patterns.push(pattern),
                            Err(err) => {
                                eprintln!("Invalid regex pattern '{}': {}", pattern, err);
                                success = false;
                            }
                        }
                    }
                    self.suspicious_patterns = valid_patterns;
                }
                _ => {
                    eprintln!("Unknown configuration field '{}'", field);
                    success = false;
                }
            }
        }
        success
    }
}

// Implementation of additional methods for AnomalyDetector
impl AnomalyDetector {
    // Initialise file monitoring
    pub fn init_file_monitoring(&mut self) {
        let (tx, rx) = channel();

        // Create a watcher object, delivering events
        let mut watcher = notify::recommended_watcher(tx).unwrap();

        // Monitor the user's home directory
        let home_dir = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/home"));
        watcher.watch(&home_dir, RecursiveMode::Recursive).unwrap();

        // Clone the Arc<Mutex<Vec<String>>> to share with the thread
        let file_events_clone = Arc::clone(&self.file_events);

        // Spawn a thread to handle file events
        std::thread::spawn(move || {
            for res in rx {
                match res {
                    Ok(event) => {
                        // Handle access events
                        if let Event { kind: EventKind::Access(_), paths, .. } = event {
                            if let Some(path) = paths.first() {
                                if let Some(file_name) = path.to_str() {
                                    let mut events = file_events_clone.lock().unwrap();
                                    events.push(file_name.to_string());
                                }
                            }
                        }
                    },
                    Err(e) => eprintln!("Watch error: {:?}", e),
                }
            }
        });
    }

    // Fetch recent commands executed by the current user using 'ps' command
    fn fetch_recent_command(&mut self) -> Option<(String, String)> {
        let current_pid = process::id();

        let output = Command::new("ps")
            .arg("-eo")
            .arg("pid,uid,tty,comm,etimes")
            .output()
            .expect("Failed to execute ps command");

        let data = String::from_utf8_lossy(&output.stdout);

        let current_uid = users::get_current_uid();

        let mut recent_commands = Vec::new();

        for line in data.lines().skip(1) {
            let parts: Vec<&str> = line.trim_start().split_whitespace().collect();
            if parts.len() < 5 {
                continue;
            }

            let pid = match parts[0].parse::<u32>() {
                Ok(p) => p,
                Err(_) => continue,
            };
            let uid = match parts[1].parse::<u32>() {
                Ok(u) => u,
                Err(_) => continue,
            };
            let tty = parts[2].to_string();
            let command = parts[3].to_string();
            let etime = match parts[4].parse::<u64>() {
                Ok(e) => e,
                Err(_) => continue,
            };

            // Exclude the current process and root processes
            if pid == current_pid || uid == 0 || uid != current_uid {
                continue;
            }

            // Only consider processes associated with a terminal (TTY)
            if !tty.starts_with("pts/") && !tty.starts_with("tty") {
                continue;
            }

            // Exclude known safe commands
            if self.known_safe_commands.contains(&command) {
                continue;
            }

            // Check if we've already seen this command
            let command_key = format!("{}:{}", pid, command);
            if self.seen_commands.contains(&command_key) {
                continue;
            }

            // Get process start time
            let start_timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                .saturating_sub(etime);

            // Check if the command was started after the last check
            if start_timestamp > self.last_command_timestamp {
                // Convert UID to username
                let user_name = match users::get_user_by_uid(uid) {
                    Some(user) => user.name().to_string_lossy().into_owned(),
                    None => continue,
                };

                recent_commands.push((user_name, command));
            }

            // Add the command to seen_commands
            self.seen_commands.insert(command_key);
        }

        // Update the last_command_timestamp
        self.last_command_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Return the most recent command
        recent_commands.last().cloned()
    }

    // Compile suspicious command patterns
    fn suspicious_command_patterns(&self) -> Vec<Regex> {
        self.suspicious_patterns
            .iter()
            .filter_map(|pattern| Regex::new(pattern).ok())
            .collect()
    }

    // Fetch current CPU usage from top command
    fn fetch_cpu_usage(&self) -> f32 {
        let output = Command::new("top")
            .arg("-bn1")
            .output()
            .expect("Failed to execute top command");
        let data = String::from_utf8_lossy(&output.stdout);

        // Process and extract the CPU usage information
        let cpu_usage = data.lines()
            .find(|line| line.contains("%Cpu(s)"))
            .and_then(|line| {
                let parts: Vec<&str> = line.split(',').collect();
                if let Some(idle_part) = parts.last() {
                    let idle_str = idle_part.trim().split_whitespace().next().unwrap_or("0");
                    if let Ok(idle) = idle_str.parse::<f32>() {
                        Some(100.0 - idle)
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .unwrap_or(0.0);

        cpu_usage
    }

    // Fetch current memory usage from free command
    fn fetch_memory_usage(&self) -> f32 {
        let output = Command::new("free")
            .arg("-m")
            .output()
            .expect("Failed to execute free command");
        let data = String::from_utf8_lossy(&output.stdout);

        // Process and extract memory usage information
        let memory_usage = data.lines()
            .find(|line| line.starts_with("Mem:"))
            .and_then(|line| {
                let parts: Vec<&str> = line.split_whitespace().collect();
                let total_mem: f32 = parts.get(1)?.parse().unwrap_or(1.0);  // Total memory
                let used_mem: f32 = parts.get(2)?.parse().unwrap_or(0.0);   // Used memory
                Some((used_mem / total_mem) * 100.0)
            })
            .unwrap_or(0.0);

        memory_usage
    }

    // Check for network packet drops using 'ip' command
    fn check_network_packet_drops(&self) -> String {
        let output = Command::new("ip")
            .arg("-s")
            .arg("link")
            .output();

        match output {
            Ok(output) => {
                let data = String::from_utf8_lossy(&output.stdout);

                // Process and extract packet drop statistics
                let mut drop_count: u32 = 0;

                for line in data.lines() {
                    if line.trim_start().starts_with("RX:") || line.trim_start().starts_with("TX:") {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if let Some(dropped_str) = parts.get(4) {
                            if let Ok(dropped) = dropped_str.parse::<u32>() {
                                drop_count += dropped;
                            }
                        }
                    }
                }

                if drop_count > 0 {
                    format!("{} dropped packets", drop_count)
                } else {
                    String::new() // No dropped packets
                }
            },
            Err(_) => {
                String::new()
            }
        }
    }

    // Fetch disk usage from df command and check for changes
    fn check_disk_changes_and_usage(&mut self) -> Vec<String> {
        let output = Command::new("df")
            .arg("-h")
            .output()
            .expect("Failed to execute df command");
        let data = String::from_utf8_lossy(&output.stdout);

        let mut logs: Vec<String> = Vec::new();
        let mut current_disks: Vec<DiskState> = Vec::new();

        for line in data.lines().skip(1) { // Skipping the header row
            let disk_info: Vec<&str> = line.split_whitespace().collect();
            if disk_info.len() < 6 || !disk_info[0].starts_with("/dev") {
                continue; // Only interested in /dev drives
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

            // Check for abnormal usage (>20% increase)
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

    // Update CPU and memory history, keeping track of the last 10 runs
    fn update_cpu_memory_history(&mut self, cpu: f32, memory: f32) {
        if self.cpu_history.len() >= MAX_RUNS {
            self.cpu_history.remove(0); // Remove the oldest entry
        }
        if self.memory_history.len() >= MAX_RUNS {
            self.memory_history.remove(0); // Remove the oldest entry
        }
        self.cpu_history.push(cpu);       // Add the latest CPU usage
        self.memory_history.push(memory); // Add the latest memory usage
    }

    // Calculate average CPU usage
    fn average_cpu_usage(&self) -> f32 {
        let sum: f32 = self.cpu_history.iter().sum();
        sum / self.cpu_history.len() as f32
    }

    // Calculate average memory usage
    fn average_memory_usage(&self) -> f32 {
        let sum: f32 = self.memory_history.iter().sum();
        sum / self.memory_history.len() as f32
    }

    // Check for anomalous CPU usage
    fn check_anomalous_cpu_usage(&self, current_cpu: f32) -> bool {
        if self.cpu_history.len() < MAX_RUNS {
            // Not enough data to compare
            return false;
        }
        current_cpu > self.average_cpu_usage() * 1.2
    }

    // Check for anomalous memory usage
    fn check_anomalous_memory_usage(&self, current_memory: f32) -> bool {
        if self.memory_history.len() < MAX_RUNS {
            // Not enough data to compare
            return false;
        }
        current_memory > self.average_memory_usage() * 1.2
    }
}

// Implement Default for AnomalyDetector
impl Default for AnomalyDetector {
    fn default() -> Self {
        let mut detector = Self {
            current_data: SystemData {
                file_name: String::new(),
                command_executed: String::new(),
                user: String::new(),
                cpu_usage: 0.0,
                memory_usage: 0.0,
            },
            history_of_filenames: vec![],
            known_safe_commands: vec![
                "ls".into(),
                "cat".into(),
                "cd".into(),
                "echo".into(),
                "vim".into(),
                "nano".into(),
                "ps".into(),
                "grep".into(),
                "top".into(),
                // Add any other default safe commands here
            ],
            known_safe_files: vec![
                "/etc/passwd".into(),
                "/var/log/syslog".into(),
                "/home/user/.bashrc".into(),
                // If there is any other default safe files - add here 
            ],
            known_unsafe_commands: vec![
                "rm".into(),
                "sudo".into(),
                "dd".into(),
                "mkfs".into(),
                "fdisk".into(),
            ],
            known_unsafe_files: vec![
                // add any default unsafe files here
            ],
            suspicious_patterns: vec![
                r"\b(rm|dd|nc|netcat|telnet|chmod|chown|kill|sudo|nmap|ftp|curl|wget)\b".into()
            ],
            module_name: String::from("AnomalyDetectionModule"),
            cpu_history: vec![],
            memory_history: vec![],
            previous_disks: vec![],
            seen_commands: HashSet::new(),
            last_command_timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            file_events: Arc::new(Mutex::new(Vec::new())),
        };

        // Initialise file monitoring
        detector.init_file_monitoring();

        detector
    }
}

