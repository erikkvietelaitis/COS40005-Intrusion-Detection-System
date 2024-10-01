use crate::lara_core::core_enums::*;
use crate::lara_core::core_structs::*;
use crate::lara_core::core_traits::AnalysisModule;
use std::collections::{HashMap, HashSet, VecDeque};
use std::process::Command;
use std::sync::{Arc, Mutex};
use regex::Regex;
use notify::{Watcher, RecursiveMode, Config};
use notify::event::{Event, EventKind, ModifyKind, AccessKind, CreateKind};
use std::path::{PathBuf, Path};
use std::os::unix::fs::MetadataExt;
use std::io::Error as IoError;

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
    permission_changes: Arc<Mutex<HashMap<String, (u32, u32)>>>,
    new_files: Arc<Mutex<Vec<String>>>,
    suspicious_files: HashSet<String>,
    watcher: notify::RecommendedWatcher,
    watched_paths: Vec<PathBuf>,
    secure_folders: Vec<PathBuf>,
    authorized_users: HashSet<String>,
    protected_files: HashSet<String>,
    allowed_files: HashSet<String>,
}

impl Default for AnomalyDetector {
    fn default() -> Self {
        let file_events = Arc::new(Mutex::new(HashMap::new()));
        let permission_changes = Arc::new(Mutex::new(HashMap::new()));
        let new_files = Arc::new(Mutex::new(Vec::new()));
        
        let detector = AnomalyDetector {
            current_data: SystemData {
                recent_commands: VecDeque::new(),
                cpu_usage: 0.0,
                memory_usage: 0.0,
            },
            suspicious_commands: ["sudo", "rm", "telnet", "wget"].iter().map(|&s| s.to_string()).collect(),
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
            permission_changes,
            new_files,
            suspicious_files: ["/etc/passwd", "/etc/shadow"].iter().map(|&s| s.to_string()).collect(),
            watcher: notify::recommended_watcher(|_: Result<Event, notify::Error>| {}).unwrap(),
            watched_paths: vec![
                PathBuf::from("/home"),
                PathBuf::from("/tmp"),
                PathBuf::from("/var/log"),
            ],
            secure_folders: vec![
                PathBuf::from("/etc"),
                PathBuf::from("/var"),
            ],
            authorized_users: ["root", "admin"].iter().map(|&s| s.to_string()).collect(),
            protected_files: ["/etc/passwd", "/etc/shadow", "/etc/sudoers"].iter().map(|&s| s.to_string()).collect(),
            allowed_files: HashSet::new(),
        };
        
        detector
    }
}

impl AnalysisModule for AnomalyDetector {
    fn get_data(&mut self) -> bool {
        match self.fetch_recent_commands() {
            Ok(_) => {},
            Err(e) => {
                println!("Error fetching recent commands: {:?}", e);
                return false;
            }
        }

        match self.fetch_cpu_usage() {
            Ok(cpu) => self.current_data.cpu_usage = cpu,
            Err(e) => {
                println!("Error fetching CPU usage: {:?}", e);
                return false;
            }
        }

        match self.fetch_memory_usage() {
            Ok(mem) => self.current_data.memory_usage = mem,
            Err(e) => {
                println!("Error fetching memory usage: {:?}", e);
                return false;
            }
        }

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
        results.append(&mut self.analyze_permission_changes());
        results.append(&mut self.analyze_new_files());

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
            ConfigField::new(
                "SecureFolders".to_owned(),
                "List of secure folders to monitor for new file additions".to_owned(),
                ConfigFieldType::String,
                self.secure_folders.iter().map(|p| p.to_string_lossy().into_owned()).collect(),
                true
            ),
            ConfigField::new(
                "AuthorizedUsers".to_owned(),
                "List of users authorized to make changes to monitored files".to_owned(),
                ConfigFieldType::String,
                self.authorized_users.iter().cloned().collect(),
                true
            ),
            ConfigField::new(
                "ProtectedFiles".to_owned(),
                "List of files that require special permission to modify".to_owned(),
                ConfigFieldType::String,
                self.protected_files.iter().cloned().collect(),
                true
            ),
            ConfigField::new(
                "AllowedFiles".to_owned(),
                "List of files that are allowed to be modified".to_owned(),
                ConfigFieldType::String,
                self.allowed_files.iter().cloned().collect(),
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
                    self.watched_paths = vals.into_iter()
                        .map(PathBuf::from)
                        .filter(|p| p.exists())
                        .collect();
                }
                "SecureFolders" => {
                    self.secure_folders = vals.into_iter()
                        .map(PathBuf::from)
                        .filter(|p| p.exists() && p.is_dir())
                        .collect();
                }
                "AuthorizedUsers" => {
                    self.authorized_users = vals.into_iter().collect();
                }
                "ProtectedFiles" => {
                    self.protected_files = vals.into_iter().collect();
                }
                "AllowedFiles" => {
                    self.allowed_files = vals.into_iter().collect();
                }
                _ => {}
            }
        }
        self.update_watcher();
        true
    }
}

impl AnomalyDetector {
    fn fetch_recent_commands(&mut self) -> Result<(), IoError> {
        let output = Command::new("ps")
            .arg("-eo")
            .arg("user,command")
            .output()?;

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
        Ok(())
    }

    fn fetch_cpu_usage(&self) -> Result<f32, IoError> {
        let output = Command::new("top")
            .arg("-bn1")
            .output()?;
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
            .map(|idle| Ok(100.0 - idle))
            .unwrap_or(Err(IoError::new(std::io::ErrorKind::Other, "Failed to parse CPU usage")))
    }

    fn fetch_memory_usage(&self) -> Result<f32, IoError> {
        let output = Command::new("free")
            .arg("-m")
            .output()?;
        let data = String::from_utf8_lossy(&output.stdout);

        data.lines()
            .find(|line| line.starts_with("Mem:"))
            .and_then(|line| {
                let parts: Vec<&str> = line.split_whitespace().collect();
                let total_mem: f32 = parts.get(1)?.parse().unwrap_or(1.0);
                let used_mem: f32 = parts.get(2)?.parse().unwrap_or(0.0);
                Some((used_mem / total_mem) * 100.0)
            })
            .ok_or_else(|| IoError::new(std::io::ErrorKind::Other, "Failed to parse memory usage"))
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

    fn is_suspicious_command(&self, command: &str) -> bool {
        // Whitelist common system processes
        let whitelist = [
            "/usr/bin/gnome-terminal",
            "/usr/libexec/gnome-terminal-server",
        ];

        if whitelist.iter().any(|&safe_cmd| command.starts_with(safe_cmd)) {
            return false;
        }

        self.suspicious_commands.iter().any(|sus_cmd| {
            command.split_whitespace().any(|word| word == sus_cmd)
        })
    }

  fn analyze_commands(&self) -> Vec<Log> {
        let mut results = Vec::new();

        println!("Analyzing {} recent commands", self.current_data.recent_commands.len());

        for (user, command) in &self.current_data.recent_commands {
            if self.is_suspicious_command(command) {
                // Check if the user is a system user (UID < 1000 typically)
                if let Ok(output) = Command::new("id").arg("-u").arg(user).output() {
                    if let Ok(uid) = String::from_utf8_lossy(&output.stdout).trim().parse::<u32>() {
                        if uid >= 1000 {  // Non-system user
                            println!("Detected suspicious command: {}", command);
                            results.push(Log::new(
                                LogType::Warning,
                                self.module_name.clone(),
                                format!("Suspicious command executed by {}: {}", user, command),
                            ));
                        }
                    }
                }
            }

            for pattern in &self.suspicious_patterns {
                if pattern.is_match(command) {
                    println!("Detected suspicious pattern in command: {}", command);
                    results.push(Log::new(
                        LogType::Warning,
                        self.module_name.clone(),
                        format!("Suspicious command pattern matched by {}: {}", user, command),
                    ));
                    break;
                }
            }
        }

        println!("Command analysis complete. Found {} suspicious commands", results.len());
        results
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

    fn is_authorized_change(&self, user: &str, file: &str) -> bool {
        self.authorized_users.contains(user) || 
        self.allowed_files.contains(file)
    }

    fn analyze_permission_changes(&self) -> Vec<Log> {
        let mut results = Vec::new();
        
        if let Ok(changes) = self.permission_changes.lock() {
            for (path, (old_mode, new_mode)) in changes.iter() {
                if old_mode != new_mode {
                    let metadata = std::fs::metadata(path).expect("Failed to get metadata");
                    let owner_uid = metadata.uid();
                    let owner_user = Command::new("id")
                        .arg("-nu")
                        .arg(owner_uid.to_string())
                        .output()
                        .expect("Failed to execute process");
                    let owner_user_str = String::from_utf8_lossy(&owner_user.stdout).trim().to_string();

                    if self.is_authorized_change(&owner_user_str, path) {
                        results.push(Log::new(
                            LogType::Info,
                            self.module_name.clone(),
                            format!("Authorized permission change: {} (old: {:o}, new: {:o}) by user {}", path, old_mode, new_mode, owner_user_str),
                        ));
                    } else if self.protected_files.contains(path) {
                        results.push(Log::new(
                            LogType::Warning,
                            self.module_name.clone(),
                            format!("Unauthorized permission change detected on protected file: {} (old: {:o}, new: {:o}) by user {}", path, old_mode, new_mode, owner_user_str),
                        ));
                    } else {
                        results.push(Log::new(
                            LogType::Info,
                            self.module_name.clone(),
                            format!("Permission change on non-protected file: {} (old: {:o}, new: {:o}) by user {}", path, old_mode, new_mode, owner_user_str),
                        ));
                    }
                }
            }
        }
        
        results
    }

    fn analyze_new_files(&self) -> Vec<Log> {
        let mut results = Vec::new();
        
        if let Ok(files) = self.new_files.lock() {
            for file in files.iter() {
                let metadata = std::fs::metadata(file).expect("Failed to get metadata");
                let owner_uid = metadata.uid();
                let owner_user = Command::new("id")
                    .arg("-nu")
                    .arg(owner_uid.to_string())
                    .output()
                    .expect("Failed to execute process");
                let owner_user_str = String::from_utf8_lossy(&owner_user.stdout).trim().to_string();

                if !self.is_authorized_change(&owner_user_str, file) {
                    results.push(Log::new(
                        LogType::Warning,
                        self.module_name.clone(),
                        format!("Unauthorized new file created in secure folder: {} by user {}", file, owner_user_str),
                    ));
                } else if file.ends_with(".exe") || file.ends_with(".sh") {
                    results.push(Log::new(
                        LogType::Info,
                        self.module_name.clone(),
                        format!("Potentially suspicious new file detected in secure folder: {} by authorized user {}", file, owner_user_str),
                    ));
                } else {
                    results.push(Log::new(
                        LogType::Info,
                        self.module_name.clone(),
                        format!("New file detected in secure folder: {} by authorized user {}", file, owner_user_str),
                    ));
                }
            }
        }
        
        results
    }

    fn update_watcher(&mut self) {
        let file_events = Arc::clone(&self.file_events);
        let permission_changes = Arc::clone(&self.permission_changes);
        let new_files = Arc::clone(&self.new_files);
        let suspicious_files = self.suspicious_files.clone();
        let secure_folders = self.secure_folders.clone();
        
        let config = Config::default()
            .with_compare_contents(false)
            .with_poll_interval(std::time::Duration::from_secs(2));
        
        self.watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
            match res {
                Ok(event) => {
                    match event.kind {
                        EventKind::Access(AccessKind::Open(_)) => {
                            if let Some(path) = event.paths.first() {
                                if path.exists() && suspicious_files.contains(&path.to_string_lossy().into_owned()) {
                                    if let Some(path_str) = path.to_str() {
                                        let mut events = file_events.lock().unwrap();
                                        *events.entry(path_str.to_string()).or_insert(0) += 1;
                                    }
                                }
                            }
                        },
                        EventKind::Modify(ModifyKind::Metadata(_)) => {
                            if let Some(path) = event.paths.first() {
                                if path.exists() {
                                    if let Ok(metadata) = std::fs::metadata(path) {
                                        let new_mode = metadata.mode();
                                        let mut changes = permission_changes.lock().unwrap();
                                        if let Some(path_str) = path.to_str() {
                                            changes.entry(path_str.to_string())
                                                .and_modify(|(old, current)| {
                                                    if *current != new_mode {
                                                        *old = *current;
                                                        *current = new_mode;
                                                    }
                                                })
                                                .or_insert((new_mode, new_mode));
                                        }
                                    }
                                }
                            }
                        },
                        EventKind::Create(CreateKind::File) => {
                            if let Some(path) = event.paths.first() {
                                if secure_folders.iter().any(|folder| path.starts_with(folder)) {
                                    if let Some(path_str) = path.to_str() {
                                        let mut files = new_files.lock().unwrap();
                                        files.push(path_str.to_string());
                                    }
                                }
                            }
                        },
                        _ => {}
                    }
                },
                Err(e) => println!("Watch error: {:?}", e),
            }
        }).unwrap();

        // Update watched paths
        for path in self.watched_paths.iter().chain(self.secure_folders.iter()) {
            if path.is_dir() {
                if let Err(e) = self.watcher.watch(path, RecursiveMode::Recursive) {
                    println!("Error watching {}: {:?}", path.display(), e);
                } else {
                    println!("Now watching: {}", path.display());
                }
            } else {
                println!("Skipping non-directory path: {}", path.display());
            }
        }
    }

    pub fn manual_analysis(&mut self) -> Vec<Log> {
        println!("Starting manual analysis...");
        self.get_data();
        let logs = self.perform_analysis();
        println!("Analysis complete. {} logs generated.", logs.len());
        for log in &logs {
            println!("Log: {}", log.build_alert());
        }
        logs
    }
}
