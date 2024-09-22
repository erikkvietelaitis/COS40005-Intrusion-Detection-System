use crate::lara_core::*;
use core_traits::AnalysisModule;
use regex::Regex;
use std::process::Command;
use std::collections::{HashMap, HashSet};
use crate::ConfigField;
use core_enums::*;
use users::{self, os::unix::UserExt};
use std::process;
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use notify::{RecommendedWatcher, RecursiveMode, Watcher, EventKind, Event};
use std::sync::{Arc, Mutex};
use std::sync::mpsc::channel;
use std::path::PathBuf;
use dirs;
use chrono;
use colored::*;

const MAX_RUNS: usize = 10;

#[derive(Clone, Debug)]
struct DiskState {
    filesystem: String,
    size: String,
    used: String,
    avail: String,
    use_percent: f32,
}

#[derive(Debug, Clone)]
struct SystemData {
    file_name: String,
    command_executed: String,
    user: String,
    cpu_usage: f32,
    memory_usage: f32,
}

pub struct AnomalyDetector {
    current_data: SystemData,
    history_of_filenames: Vec<String>,
    known_safe_commands: HashSet<String>,
    known_safe_files: HashSet<String>,
    known_unsafe_commands: HashSet<String>,
    known_unsafe_files: HashSet<String>,
    suspicious_patterns: Vec<String>,
    module_name: String,
    cpu_history: Vec<f32>,
    memory_history: Vec<f32>,
    previous_disks: Vec<DiskState>,
    last_command_timestamp: u64,
    file_events: Arc<Mutex<Vec<String>>>,
    command_history: HashMap<String, Vec<(u64, String)>>,
}

impl AnalysisModule for AnomalyDetector {
    fn get_data(&mut self) -> bool {
        self.fetch_recent_commands();
        
        if let Ok(mut events) = self.file_events.lock() {
            if let Some(file_name) = events.pop() {
                self.current_data.file_name = file_name;
            } else {
                self.current_data.file_name.clear();
            }
        }

        self.current_data.cpu_usage = self.fetch_cpu_usage();
        self.current_data.memory_usage = self.fetch_memory_usage();

        self.update_cpu_memory_history(self.current_data.cpu_usage, self.current_data.memory_usage);

        true
    }

    fn get_testing_data(&mut self) -> bool {
        false
    }

    fn perform_analysis(&mut self) -> Vec<core_structs::Log> {
        let mut results: Vec<core_structs::Log> = Vec::new();

        self.analyze_commands(&mut results);
        self.analyze_file_access(&mut results);
        self.analyze_resource_usage(&mut results);
        self.analyze_network(&mut results);
        self.analyze_disk_changes(&mut results);

        if !results.is_empty() {
            println!("{}", "=== Anomaly Detection Summary ===".yellow().bold());
            for log in &results {
                match log.log_type {
                    LogType::Serious => println!("{}", log.message.red()),
                    LogType::Warning => println!("{}", log.message.yellow()),
                    _ => println!("{}", log.message),
                }
            }
            println!("{}", "================================".yellow().bold());
        }

        results
    }

    fn get_name(&self) -> String {
        self.module_name.clone()
    }

    fn build_config_fields(&self) -> Vec<ConfigField> {
        vec![
            ConfigField::new(
                "KnownSafeCommands".to_owned(),
                "List of commands considered safe".to_owned(),
                ConfigFieldType::String,
                self.known_safe_commands.iter().cloned().collect(),
                true,
            ),
            ConfigField::new(
                "KnownSafeFiles".to_owned(),
                "List of files considered safe".to_owned(),
                ConfigFieldType::String,
                self.known_safe_files.iter().cloned().collect(),
                true,
            ),
            ConfigField::new(
                "KnownUnsafeCommands".to_owned(),
                "List of commands considered unsafe".to_owned(),
                ConfigFieldType::String,
                self.known_unsafe_commands.iter().cloned().collect(),
                true,
            ),
            ConfigField::new(
                "KnownUnsafeFiles".to_owned(),
                "List of files considered unsafe".to_owned(),
                ConfigFieldType::String,
                self.known_unsafe_files.iter().cloned().collect(),
                true,
            ),
            ConfigField::new(
                "SuspiciousCommandPatterns".to_owned(),
                "Regex patterns for suspicious commands".to_owned(),
                ConfigFieldType::String,
                self.suspicious_patterns.clone(),
                true,
            ),
        ]
    }

    fn retrieve_config_data(&mut self, data: HashMap<String, Vec<String>>) -> bool {
        let mut success = true;
        for (field, vals) in data {
            match field.as_str() {
                "KnownSafeCommands" => {
                    if vals.iter().all(|cmd| !cmd.trim().is_empty()) {
                        self.known_safe_commands = vals.into_iter().collect();
                    } else {
                        eprintln!("{}", "Invalid command in KnownSafeCommands.".red());
                        success = false;
                    }
                }
                "KnownSafeFiles" => {
                    if vals.iter().all(|file| !file.trim().is_empty()) {
                        self.known_safe_files = vals.into_iter().collect();
                    } else {
                        eprintln!("{}", "Invalid file in KnownSafeFiles.".red());
                        success = false;
                    }
                }
                "KnownUnsafeCommands" => {
                    if vals.iter().all(|cmd| !cmd.trim().is_empty()) {
                        self.known_unsafe_commands = vals.into_iter().collect();
                    } else {
                        eprintln!("{}", "Invalid command in KnownUnsafeCommands.".red());
                        success = false;
                    }
                }
                "KnownUnsafeFiles" => {
                    if vals.iter().all(|file| !file.trim().is_empty()) {
                        self.known_unsafe_files = vals.into_iter().collect();
                    } else {
                        eprintln!("{}", "Invalid file in KnownUnsafeFiles.".red());
                        success = false;
                    }
                }
                "SuspiciousCommandPatterns" => {
                    let mut valid_patterns = Vec::new();
                    for pattern in vals {
                        match Regex::new(&pattern) {
                            Ok(_) => valid_patterns.push(pattern),
                            Err(err) => {
                                eprintln!("{}", format!("Invalid regex pattern '{}': {}", pattern, err).red());
                                success = false;
                            }
                        }
                    }
                    self.suspicious_patterns = valid_patterns;
                }
                _ => {
                    eprintln!("{}", format!("Unknown configuration field '{}'", field).red());
                    success = false;
                }
            }
        }
        success
    }
}

impl AnomalyDetector {
    pub fn init_file_monitoring(&mut self) {
        let (tx, rx) = channel();
        let mut watcher = notify::recommended_watcher(tx).unwrap();
        let home_dir = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/home"));
        watcher.watch(&home_dir, RecursiveMode::Recursive).unwrap();
        let file_events_clone = Arc::clone(&self.file_events);

        std::thread::spawn(move || {
            for res in rx {
                match res {
                    Ok(event) => {
                        if let Event { kind: EventKind::Access(_), paths, .. } = event {
                            if let Some(path) = paths.first() {
                                if let Some(file_name) = path.to_str() {
                                    let mut events = file_events_clone.lock().unwrap();
                                    events.push(file_name.to_string());
                                }
                            }
                        }
                    },
                    Err(e) => eprintln!("{}", format!("Watch error: {:?}", e).red()),
                }
            }
        });
    }

    fn fetch_recent_commands(&mut self) {
        let output = Command::new("ps")
            .arg("-eo")
            .arg("pid,uid,comm,args,etimes")
            .output()
            .expect("Failed to execute ps command");

        let data = String::from_utf8_lossy(&output.stdout);
        let current_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        for line in data.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 5 {
                continue;
            }

            let pid = parts[0].parse::<u32>().unwrap_or(0);
            let uid = parts[1].parse::<u32>().unwrap_or(0);
            let command = parts[2].to_string();
            let args = parts[3..parts.len()-1].join(" ");
            let etimes = parts.last().unwrap().parse::<u64>().unwrap_or(0);

            if pid == std::process::id() {
                continue;
            }

            let user = users::get_user_by_uid(uid)
                .map(|u| u.name().to_string_lossy().into_owned())
                .unwrap_or_else(|| uid.to_string());

            let timestamp = current_timestamp - etimes;

            if timestamp > self.last_command_timestamp {
                let full_command = format!("{} {}", command, args);
                if self.is_command_of_interest(&full_command) {
                    self.add_command_to_history(user, full_command, timestamp);
                }
            }
        }

        self.last_command_timestamp = current_timestamp;
    }

    fn is_command_of_interest(&self, command: &str) -> bool {
        let base_command = command.split_whitespace().next().unwrap_or("");
        !self.known_safe_commands.contains(base_command) &&
        (self.known_unsafe_commands.contains(base_command) ||
         self.suspicious_command_patterns().iter().any(|pattern| pattern.is_match(command)))
    }

    fn add_command_to_history(&mut self, user: String, command: String, timestamp: u64) {
        let entry = self.command_history.entry(user.clone()).or_insert_with(Vec::new);
        entry.push((timestamp, command.clone()));

        if entry.len() > 100 {
            entry.remove(0);
        }

        self.current_data.command_executed = command;
        self.current_data.user = user;
    }

    fn suspicious_command_patterns(&self) -> Vec<Regex> {
        self.suspicious_patterns
            .iter()
            .filter_map(|pattern| Regex::new(pattern).ok())
            .collect()
    }

    fn fetch_cpu_usage(&self) -> f32 {
        let output = Command::new("top")
            .arg("-bn1")
            .output()
            .expect("Failed to execute top command");
        let data = String::from_utf8_lossy(&output.stdout);

        data.lines()
            .find(|line| line.contains("%Cpu(s)"))
            .and_then(|line| {
                let parts: Vec<&str> = line.split(',').collect();
                parts.last()
                    .and_then(|idle_part| {
                        idle_part.trim().split_whitespace().next()
                            .and_then(|idle_str| idle_str.parse::<f32>().ok())
                            .map(|idle| 100.0 - idle)
                    })
            })
            .unwrap_or(0.0)
    }

    fn fetch_memory_usage(&self) -> f32 {
        let output = Command::new("free")
            .arg("-m")
            .output()
            .expect("Failed to execute free command");
        let data = String::from_utf8_lossy(&output.stdout);

        data.lines()
            .find(|line| line.starts_with("Mem:"))
            .and_then(|line| {
                let parts: Vec<&str> = line.split_whitespace().collect();
                let total_mem: f32 = parts.get(1)?.parse().unwrap_or(1.0);
                let used_mem: f32 = parts.get(2)?.parse().unwrap_or(0.0);
                Some((used_mem / total_mem) * 100.0)
            })
            .unwrap_or(0.0)
    }

    fn check_network_packet_drops(&self) -> String {
        let output = Command::new("ip")
            .arg("-s")
            .arg("link")
            .output();

        match output {
            Ok(output) => {
                let data = String::from_utf8_lossy(&output.stdout);
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
                    String::new()
                }
            },
            Err(_) => String::new()
        }
    }

    fn check_disk_changes_and_usage(&mut self) -> Vec<String> {
        let output = Command::new("df")
            .arg("-h")
            .output()
            .expect("Failed to execute df command");
        let data = String::from_utf8_lossy(&output.stdout);

        let mut logs: Vec<String> = Vec::new();
        let mut current_disks: Vec<DiskState> = Vec::new();

        for line in data.lines().skip(1) {
            let disk_info: Vec<&str> = line.split_whitespace().collect();
            if disk_info.len() < 6 || !disk_info[0].starts_with("/dev") {
                continue;
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

    fn update_cpu_memory_history(&mut self, cpu: f32, memory: f32) {
        if self.cpu_history.len() >= MAX_RUNS {
            self.cpu_history.remove(0);
        }
        if self.memory_history.len() >= MAX_RUNS {
            self.memory_history.remove(0);
        }
        self.cpu_history.push(cpu);
        self.memory_history.push(memory);
    }

    fn average_cpu_usage(&self) -> f32 {
        let sum: f32 = self.cpu_history.iter().sum();
        sum / self.cpu_history.len() as f32
    }

    fn average_memory_usage(&self) -> f32 {
        let sum: f32 = self.memory_history.iter().sum();
        sum / self.memory_history.len() as f32
    }

    fn analyze_commands(&self, results: &mut Vec<core_structs::Log>) {
        for (user, commands) in &self.command_history {
            for (timestamp, command) in commands {
                let msg = format!(
                    "[{}]=[{}]=[Serious]: User '{}' executed a suspicious or unsafe command '{}' at {}.",
                    chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                    self.module_name,
                    user,
                    command,
                    chrono::NaiveDateTime::from_timestamp(*timestamp as i64, 0).format("%Y-%m-%d %H:%M:%S")
                );
                results.push(core_structs::Log::new(
                    LogType::Serious,
                    self.module_name.clone(),
                    msg,
                ));
            }
        }
    }

    fn analyze_file_access(&self, results: &mut Vec<core_structs::Log>) {
        if !self.current_data.file_name.is_empty()
            && (!self.known_safe_files.contains(&self.current_data.file_name)
                || self.known_unsafe_files.contains(&self.current_data.file_name))
        {
            let msg = format!(
                "[{}]=[{}]=[Warning]: An unrecognized or unsafe file '{}' was accessed.",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                self.module_name,
                self.current_data.file_name
            );
            results.push(core_structs::Log::new(
                LogType::Warning,
                self.module_name.clone(),
                msg,
            ));
        }
    }

    fn analyze_resource_usage(&self, results: &mut Vec<core_structs::Log>) {
        if self.cpu_history.len() >= MAX_RUNS && self.current_data.cpu_usage > self.average_cpu_usage() * 1.5 {
            let msg = format!(
                "[{}]=[{}]=[Warning]: CPU usage is at {:.2}% which is significantly higher than the average of {:.2}%.",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                self.module_name,
                self.current_data.cpu_usage,
                self.average_cpu_usage()
            );
            results.push(core_structs::Log::new(
                LogType::Warning,
                self.module_name.clone(),
                msg,
            ));
        }

        if self.memory_history.len() >= MAX_RUNS && self.current_data.memory_usage > self.average_memory_usage() * 1.5 {
            let msg = format!(
                "[{}]=[{}]=[Warning]: Memory usage is at {:.2}% which is significantly higher than the average of {:.2}%.",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                self.module_name,
                self.current_data.memory_usage,
                self.average_memory_usage()
            );
            results.push(core_structs::Log::new(
                LogType::Warning,
                self.module_name.clone(),
                msg,
            ));
        }
    }

    fn analyze_network(&self, results: &mut Vec<core_structs::Log>) {
        let network_log = self.check_network_packet_drops();
        if !network_log.is_empty() {
            let msg = format!(
                "[{}]=[{}]=[Warning]: Network issues detected. {}",
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
    }

    fn analyze_disk_changes(&mut self, results: &mut Vec<core_structs::Log>) {
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
    }
}

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
            known_safe_commands: [
                "ls", "cat", "cd", "echo", "vim", "nano", "ps", "grep", "top", "bash", "sh", "zsh"
            ].iter().map(|&s| s.to_string()).collect(),
            known_safe_files: [
                "/etc/passwd", "/var/log/syslog", "/home/user/.bashrc"
            ].iter().map(|&s| s.to_string()).collect(),
            known_unsafe_commands: [
                "rm", "sudo", "dd", "mkfs", "fdisk", "telnet"
            ].iter().map(|&s| s.to_string()).collect(),
            known_unsafe_files: HashSet::new(),
            suspicious_patterns: vec![
                r"\b(nc|netcat|telnet|chmod|chown|kill|nmap|ftp|curl|wget)\b".to_string(),
                r"\brm\s+(-rf?|--recursive|--force)".to_string(),
                r"\bsudo\s+.*".to_string(),
            ],
            module_name: String::from("AnomalyDetectionModule"),
            cpu_history: vec![],
            memory_history: vec![],
            previous_disks: vec![],
            last_command_timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            file_events: Arc::new(Mutex::new(Vec::new())),
            command_history: HashMap::new(),
        };

        detector.init_file_monitoring();
        detector
    }
}

pub fn run_anomaly_detector() {
    println!("{}", "Initializing Anomaly Detector...".green());
    let mut detector = AnomalyDetector::default();

    println!("{}", "Anomaly Detector is now running. Press Ctrl+Z to stop.".green());
    loop {
        if detector.get_data() {
            let anomalies = detector.perform_analysis();
            if anomalies.is_empty() {
                println!("{}", "No anomalies detected in this cycle.".green());
            }
        } else {
            eprintln!("{}", "Failed to get data in this cycle.".red());
        }
        std::thread::sleep(Duration::from_secs(5)); // Run every 5 seconds for testing
    }
}