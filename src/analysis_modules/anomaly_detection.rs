use crate::lara_core::core_enums::*;
use crate::lara_core::core_structs::*;
use crate::lara_core::core_traits::AnalysisModule;
use std::collections::{HashMap, HashSet, VecDeque};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use regex::Regex;
use notify::{Watcher, RecursiveMode, Config};
use notify::event::{EventKind, ModifyKind, AccessKind};
use std::path::PathBuf;

const MAX_RUNS: usize = 10;
const MAX_COMMANDS: usize = 20;

#[derive(Clone, Debug)]
struct SystemData {
    recent_commands: VecDeque<(String, String)>, // (user, command)
    cpu_usage: f32,
    memory_usage: f32,
}

pub struct AnomalyDetector {
    current_data: SystemData,
    suspicious_commands: HashSet<String>,
    suspicious_patterns: Vec<Regex>,
    module_name: String,
    cpu_threshold: f32,
    memory_threshold: f32,
    cpu_history: Vec<f32>,
    memory_history: Vec<f32>,
    file_events: Arc<Mutex<HashMap<String, usize>>>,
    suspicious_files: HashSet<String>,
    watcher: notify::RecommendedWatcher,
    watched_paths: Vec<PathBuf>,
}

impl Default for AnomalyDetector {
    fn default() -> Self {
        let file_events = Arc::new(Mutex::new(HashMap::new()));
        let file_events_clone = Arc::clone(&file_events);

        let mut watcher = notify::recommended_watcher(move |res: Result<notify::Event, notify::Error>| {
            match res {
                Ok(event) => {
                    match event.kind {
                        EventKind::Modify(ModifyKind::Data(_)) | EventKind::Access(AccessKind::Open(_)) => {
                            if let Some(path) = event.paths.first() {
                                if let Some(path_str) = path.to_str() {
                                    let mut events = file_events_clone.lock().unwrap();
                                    *events.entry(path_str.to_string()).or_insert(0) += 1;
                                }
                            }
                        },
                        _ => {}
                    }
                },
                Err(e) => println!("Watch error: {:?}", e),
            }
        }).unwrap();

        let watched_paths = vec![
            PathBuf::from("/home"),
            PathBuf::from("/tmp"),
            PathBuf::from("/var/log"),
        ];

        for path in &watched_paths {
            if let Err(e) = watcher.watch(path, RecursiveMode::Recursive) {
                println!("Error watching {}: {:?}", path.display(), e);
            }
        }

        AnomalyDetector {
            current_data: SystemData {
                recent_commands: VecDeque::new(),
                cpu_usage: 0.0,
                memory_usage: 0.0,
            },
            suspicious_commands: ["sudo", "rm", "telnet", "wget"].iter().map(|&s| s.to_string()).collect(), //add more commands -- later
            suspicious_patterns: vec![
                Regex::new(r"\brm\s+(-rf?|--recursive|--force)").unwrap(),
                Regex::new(r"\bsudo\s+.*").unwrap(),
                Regex::new(r"\bwget\s+.*").unwrap(),
            ],
            module_name: String::from("AnomalyDetectionModule"),
            cpu_threshold: 80.0,
            memory_threshold: 90.0,
            cpu_history: Vec::new(),
            memory_history: Vec::new(),
            file_events,
            suspicious_files: ["/etc/passwd", "/etc/shadow"].iter().map(|&s| s.to_string()).collect(),
            watcher,
            watched_paths,
        }
    }
}

impl AnalysisModule for AnomalyDetector {
    fn get_data(&mut self) -> bool {
        self.fetch_recent_commands();
        self.current_data.cpu_usage = self.fetch_cpu_usage();
        self.current_data.memory_usage = self.fetch_memory_usage();
        self.update_cpu_memory_history(self.current_data.cpu_usage, self.current_data.memory_usage);
        true
    }

    fn get_testing_data(&mut self) -> bool {
        false
    }

    fn perform_analysis(&mut self) -> Vec<Log> {
        let mut results = Vec::new();
        
        results.append(&mut self.analyze_commands());
        results.append(&mut self.analyze_resource_usage());
        results.append(&mut self.analyze_file_access());

        results
    }

    fn get_name(&self) -> String {
        self.module_name.clone()
    }

    fn build_config_fields(&self) -> Vec<ConfigField> {
        vec![
            ConfigField::new(
                "SuspiciousCommands".to_owned(),
                "List of commands considered suspicious".to_owned(),
                ConfigFieldType::String,
                self.suspicious_commands.iter().cloned().collect(),
                true
            ),
            ConfigField::new(
                "SuspiciousPatterns".to_owned(),
                "Regex patterns for suspicious commands".to_owned(),
                ConfigFieldType::String,
                self.suspicious_patterns.iter().map(|re| re.as_str().to_owned()).collect(),
                true
            ),
            ConfigField::new(
                "CPUThreshold".to_owned(),
                "CPU usage threshold for alerts (percentage)".to_owned(),
                ConfigFieldType::Float,
                vec![self.cpu_threshold.to_string()],
                false
            ),
            ConfigField::new(
                "MemoryThreshold".to_owned(),
                "Memory usage threshold for alerts (percentage)".to_owned(),
                ConfigFieldType::Float,
                vec![self.memory_threshold.to_string()],
                false
            ),
            ConfigField::new(
                "SuspiciousFiles".to_owned(),
                "List of files considered suspicious when accessed".to_owned(),
                ConfigFieldType::String,
                self.suspicious_files.iter().cloned().collect(),
                true
            ),
            ConfigField::new(
                "WatchedPaths".to_owned(),
                "List of paths to monitor for file events".to_owned(),
                ConfigFieldType::String,
                self.watched_paths.iter().map(|p| p.to_string_lossy().into_owned()).collect(),
                true
            ),
        ]
    }

    fn retrieve_config_data(&mut self, data: HashMap<String, Vec<String>>) -> bool {
        for (field, vals) in data {
            match field.as_str() {
                "SuspiciousCommands" => {
                    self.suspicious_commands = vals.into_iter().collect();
                }
                "SuspiciousPatterns" => {
                    self.suspicious_patterns = vals.into_iter()
                        .filter_map(|p| Regex::new(&p).ok())
                        .collect();
                }
                "CPUThreshold" => {
                    if let Some(threshold) = vals.get(0).and_then(|v| v.parse().ok()) {
                        self.cpu_threshold = threshold;
                    }
                }
                "MemoryThreshold" => {
                    if let Some(threshold) = vals.get(0).and_then(|v| v.parse().ok()) {
                        self.memory_threshold = threshold;
                    }
                }
                "SuspiciousFiles" => {
                    self.suspicious_files = vals.into_iter().collect();
                }
                "WatchedPaths" => {
                    self.watched_paths = vals.into_iter().map(PathBuf::from).collect();
                    self.update_watched_paths();
                }
                _ => {}
            }
        }
        true
    }
}

impl AnomalyDetector {
    fn fetch_recent_commands(&mut self) {
        let output = Command::new("ps")
            .arg("-eo")
            .arg("user,command")
            .output()
            .expect("Failed to execute ps command");

        let data = String::from_utf8_lossy(&output.stdout);
        self.current_data.recent_commands.clear();
        for line in data.lines().skip(1) {
            let parts: Vec<&str> = line.splitn(2, char::is_whitespace).collect();
            if parts.len() == 2 {
                let user = parts[0].to_string();
                let command = parts[1].to_string();
                self.current_data.recent_commands.push_back((user, command));
                if self.current_data.recent_commands.len() > MAX_COMMANDS {
                    self.current_data.recent_commands.pop_front();
                }
            }
        }
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
                parts.first()
                    .and_then(|idle_part| {
                        idle_part.split_whitespace().nth(1)
                            .and_then(|cpu_str| cpu_str.parse::<f32>().ok())
                    })
            })
            .map(|idle| 100.0 - idle)
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

    fn analyze_commands(&self) -> Vec<Log> {
        let mut results = Vec::new();

        for (user, command) in &self.current_data.recent_commands {
            if self.is_suspicious_command(command) {
                results.push(Log::new(
                    LogType::Warning,
                    self.module_name.clone(),
                    format!("Suspicious command executed by {}: {}", user, command),
                ));
            }

            for pattern in &self.suspicious_patterns {
                if pattern.is_match(command) {
                    results.push(Log::new(
                        LogType::Warning,
                        self.module_name.clone(),
                        format!("Suspicious command pattern matched by {}: {}", user, command),
                    ));
                    break;
                }
            }
        }

        results
    }

    fn is_suspicious_command(&self, command: &str) -> bool {
        self.suspicious_commands.iter().any(|sus_cmd| command.contains(sus_cmd))
    }

    fn analyze_resource_usage(&self) -> Vec<Log> {
        let mut results = Vec::new();

        if self.cpu_history.len() >= MAX_RUNS && self.current_data.cpu_usage > self.cpu_threshold {
            results.push(Log::new(
                LogType::Warning,
                self.module_name.clone(),
                format!("CPU usage is high: {:.2}%", self.current_data.cpu_usage),
            ));
        }

        if self.memory_history.len() >= MAX_RUNS && self.current_data.memory_usage > self.memory_threshold {
            results.push(Log::new(
                LogType::Warning,
                self.module_name.clone(),
                format!("Memory usage is high: {:.2}%", self.current_data.memory_usage),
            ));
        }

        results
    }

    fn analyze_file_access(&self) -> Vec<Log> {
        let mut results = Vec::new();

        if let Ok(events) = self.file_events.lock() {
            for (file_name, count) in events.iter() {
                if self.suspicious_files.contains(file_name) && *count > 1 {
                    results.push(Log::new(
                        LogType::Warning,
                        self.module_name.clone(),
                        format!("Suspicious file accessed multiple times: {} ({})", file_name, count),
                    ));
                }
            }
        }

        results
    }

    fn update_watched_paths(&mut self) {
        // Stop watching all current paths
        for path in &self.watched_paths {
            let _ = self.watcher.unwatch(path);
        }

        // Start watching the new paths
        for path in &self.watched_paths {
            if let Err(e) = self.watcher.watch(path, RecursiveMode::Recursive) {
                println!("Error watching {}: {:?}", path.display(), e);
            }
        }
    }
}
