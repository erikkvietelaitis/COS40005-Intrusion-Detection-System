use crate::LaraCore::*;
use CoreTraits::AnalysisModule;
use port_scanner::scan_ports_range; // Import the necessary functions and structs from the port_scanner crate
use std::collections::HashSet;


// Define the Networking struct which will handle the scanning of ports
pub struct Networking {
    pub module_name: String,
    pub current_data: CurrentNetworkData,
    pub expected_open_ports: HashSet<u16>,
    pub expected_blocked_ports: HashSet<u16>,
    pub last_scanned_port: u16, // Track the last scanned port
    pub max_ports: u16, // Maximum number of ports in the range
    pub alerted_ports: HashSet<u16>, // Keep track of ports that have generated alerts
    pub previously_closed_ports: HashSet<u16>, // Track ports that were previously closed
}

#[derive(Debug, Clone)]
pub struct CurrentNetworkData {
    pub start_port: u16,
    pub end_port: u16,
    pub open_ports: Vec<u16>,
}

impl Networking {
    // Utility function to calculate expected blocked ports
    fn calculate_blocked_ports(expected_open_ports: &HashSet<u16>, max_ports: u16) -> HashSet<u16> {
        let all_ports: HashSet<u16> = (1..=max_ports).collect();
        all_ports.difference(expected_open_ports).cloned().collect()
    }

    // Generate alerts for new unique ports
    fn generate_unique_alerts(&mut self, open_ports: &HashSet<u16>, blocked_ports: &HashSet<u16>) -> Vec<CoreStruts::Log> {
        let mut results = Vec::new();

        // Check for expected open ports that are not found
        for &port in self.expected_open_ports.iter() {
            if !open_ports.contains(&port) && !self.alerted_ports.contains(&port) {
                let msg = format!("Alert: Expected open port {} is closed.", port);
                results.push(CoreStruts::Log::new(CoreEnums::LogType::Serious, self.module_name.clone(), msg));
                self.alerted_ports.insert(port);
                self.previously_closed_ports.insert(port);
            }
        }

        // Check for previously closed ports that are now open
        for &port in open_ports.iter() {
            if self.previously_closed_ports.contains(&port) {
                let msg = format!("Alert: Previously closed port {} is now open.", port);
                results.push(CoreStruts::Log::new(CoreEnums::LogType::Serious, self.module_name.clone(), msg));
                self.previously_closed_ports.remove(&port); // Remove from previously closed set
            }
        }

        // Check for expected blocked ports that are found
        for &port in blocked_ports.iter() {
            if open_ports.contains(&port) && !self.alerted_ports.contains(&port) {
                let msg = format!("Alert: Expected blocked port {} is open.", port);
                results.push(CoreStruts::Log::new(CoreEnums::LogType::Serious, self.module_name.clone(), msg));
                self.alerted_ports.insert(port);
            }
        }

        results
    }

    // Log the current port range and generated alerts to the terminal
    fn log_scan_results(&self) {
        println!("Scanning ports from {} to {}", self.current_data.start_port, self.current_data.end_port);
    }

    fn log_generated_alerts(&self, alerts: &[CoreStruts::Log]) {
        if alerts.is_empty() {
            println!("No new alerts generated.");
        } else {
            for alert in alerts {
                println!("{}", alert.build_alert());
            }
        }
    }
}

impl AnalysisModule for Networking {
    // Use this to gather data from the host computer and store it in the current data struct
    fn get_data(&mut self) -> bool {
        // Calculate the next range of ports to scan
        let start_port = self.last_scanned_port + 1;
        let end_port = start_port.saturating_add(500).min(self.max_ports); // Safe addition with overflow handling

        // Scan the local ports
        let open_ports = scan_ports_range(start_port..end_port);

        self.current_data = CurrentNetworkData {
            start_port,
            end_port,
            open_ports: open_ports.clone(),
        };

        // Log the current port range being scanned
        self.log_scan_results();

        // Update the last scanned port
        self.last_scanned_port = if end_port == self.max_ports {
            0 // Reset to the beginning if we reach the end
        } else {
            end_port
        };

        true
    }

    // Can leave this for todo until testing. It should do the same as get_data but return a consistent predictable dataset to current data. It will be used for unit testing
    fn get_testing_data(&mut self) -> bool {
        todo!()
    }

    // Take the current data gathered from one of the functions above, using this data, plus the persistent data stored in the object to create logs (AKA alerts)
    fn perform_analysis(&mut self) -> Vec<crate::Log> {
        let mut results = Vec::new();

        let open_ports: HashSet<u16> = self.current_data.open_ports.iter().cloned().collect();
        let blocked_ports = Networking::calculate_blocked_ports(&self.expected_open_ports, self.max_ports);

        // Generate unique alerts based on the current open ports and expected blocked ports
        let alerts = self.generate_unique_alerts(&open_ports, &blocked_ports);

        // Log the generated alerts
        self.log_generated_alerts(&alerts);

        results.extend(alerts);

        results
    }

    fn get_name(&self) -> String {
        self.module_name.clone()
    }
}

// Default implementation
impl Default for Networking {
    fn default() -> Self {
        let expected_open_ports: HashSet<u16> = [80, 443, 22].iter().cloned().collect();
        let expected_blocked_ports = Networking::calculate_blocked_ports(&expected_open_ports, 65535);

        Self {
            module_name: String::from("Networking"),
            current_data: CurrentNetworkData {
                start_port: 1,
                end_port: 100,
                open_ports: Vec::new(),
            },
            expected_open_ports,
            expected_blocked_ports,
            last_scanned_port: 0,
            max_ports: 65535, // Define the total number of ports to scan
            alerted_ports: HashSet::new(), // Initialize the set of alerted ports
            previously_closed_ports: HashSet::new(), // Initialize the set of previously closed ports
        }
    }
}

// Clone implementation
impl Clone for Networking {
    fn clone(&self) -> Self {
        Self {
            module_name: self.module_name.clone(),
            current_data: self.current_data.clone(),
            expected_open_ports: self.expected_open_ports.clone(),
            expected_blocked_ports: self.expected_blocked_ports.clone(),
            last_scanned_port: self.last_scanned_port,
            max_ports: self.max_ports,
            alerted_ports: self.alerted_ports.clone(),
            previously_closed_ports: self.previously_closed_ports.clone(),
        }
    }
}
