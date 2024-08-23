// Anomaly Detection Module Summary : 
        // Monitors and detects system activities.
        // Detects potential system threats 

// Crates and Modules needed
use rand::Rng; // generating random data
use regex::Regex; // pattern matching 
use serde_json::json; // formatting alerts as JSON
use chrono::Utc; // handling timestamps


mod anomaly_detector {
    use super::*;

    
    #[derive(Debug, Copy, Clone)]
    pub struct SystemData<'a> { //This holds information about system activities during a specific time.
        pub file_name: &'a str,                        // Name of the file being accessed
        pub command_executed: &'a str,                // Command that was executed
        pub network_activity: f32,                   // Amount of network activity observed
        pub timestamp: chrono::DateTime<Utc>,       // Timestamp of the data collection
    }

    
    pub struct AnomalyDetector<'a> { // This holds the current data, history, safe lists, and logger.
        pub current_data: SystemData<'a>,               // Data captured during the current tick
        pub previous_data: Vec<SystemData<'a>>,        // History of previous data for comparison
        pub known_safe_commands: Vec<&'a str>,        // List of commands considered safe
        pub known_safe_files: Vec<&'a str>,          // List of files considered safe
    }

    impl<'a> AnomalyDetector<'a> {
        // Constructor to starts the AnomalyDetector with default values
        pub fn new() -> Self {
            Self {
                current_data: SystemData {
                    file_name: "",
                    command_executed: "",
                    network_activity: 0.0,
                    timestamp: Utc::now(),
                },
                previous_data: vec![],
                known_safe_commands: vec!["ls", "cat", "cd", "echo"], 
                known_safe_files: vec!["/etc/passwd", "/var/log/syslog", "/home/user/.bashrc"], 
            }
        }

        // Simulate gathering data from the system
        pub fn get_data(&mut self) -> bool {
            let commands: Vec<&str> = vec!["ls", "cat", "rm", "wget"];
            let files: Vec<&str> = vec!["/etc/passwd", "/var/log/syslog", "/home/user/.bashrc"];

            self.current_data = SystemData {
                file_name: files[rand::thread_rng().gen_range(0..files.len())],
                command_executed: commands[rand::thread_rng().gen_range(0..commands.len())],
                network_activity: rand::thread_rng().gen_range(0.0..1000.0),
                timestamp: Utc::now(),
            };
            true
        }

        // Analyses the collected data for anomalies
        pub fn perform_analysis(&mut self) -> Vec<String> {
            let mut results: Vec<String> = Vec::new();

        
            let suspicious_pattern = Regex::new(r"rm").unwrap();

            // Check if the command is unrecognized or matches a suspicious pattern
            if !self.known_safe_commands.contains(&self.current_data.command_executed) || suspicious_pattern.is_match(self.current_data.command_executed) {
                let msg = format!(
                    "⚠️ Anomaly detected: Unrecognized or suspicious command executed: '{}'.",
                    self.current_data.command_executed
                );
                println!("{}", msg); // Prints the message
                results.push(msg);
            }

            // Check if the file being accessed is unrecognized
            if !self.known_safe_files.contains(&self.current_data.file_name) {
                let msg = format!(
                    "🚨 Anomaly detected: Access to an unrecognized file: '{}'.",
                    self.current_data.file_name
                );
                println!("{}", msg); // Prints the message
                results.push(msg);
            }

            // Check if the network activity is unusually high
            if self.current_data.network_activity > 900.0 {
                let msg = format!(
                    "⚡ Anomaly detected: High network activity observed: {:.2} units.",
                    self.current_data.network_activity
                );
                println!("{}", msg); // Prints the message
                results.push(msg);
            }

            // JSON formatting for the results
            let json_alert = json!({
                "timestamp": self.current_data.timestamp.to_rfc3339(),
                "alert": results,
            });

            println!("{}", json_alert.to_string()); // Prints the message

            self.previous_data.push(self.current_data);
            results
        }
    } // Unit testing needed 
} // should use c

// Main function 
fn main() {
    let mut detector = anomaly_detector::AnomalyDetector::new();

    detector.get_data(); 
    let analysis_results = detector.perform_analysis(); 

    // Output the results
    if analysis_results.is_empty() {
        println!("✅ No anomalies detected. System is operating normally.");
    } else {
        for result in analysis_results {
            println!("{}", result);
        }
    }
} 