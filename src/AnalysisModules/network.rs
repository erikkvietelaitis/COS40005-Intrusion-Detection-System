use std::collections::{HashSet, HashMap};
use crate::{ConfigField, LaraCore::*};
use CoreTraits::AnalysisModule;
use port_scanner::scan_ports_range; // Ensure this is correctly imported

// Define the Networking struct which will handle the scanning of ports
pub struct Networking {
    pub module_name: String,
    pub current_data: CurrentNetworkData,
    pub expected_open_ports: HashSet<u16>,
    pub expected_blocked_ports: HashSet<u16>,
    pub last_scanned_port: u16,
    pub max_ports: u16,
    pub alerted_ports: HashSet<u16>,
    pub previously_closed_ports: HashSet<u16>,
}

#[derive(Debug, Clone)]
pub struct CurrentNetworkData {
    pub start_port: u16,
    pub end_port: u16,
    pub open_ports: Vec<u16>,
}

impl Networking {
    fn calculate_blocked_ports(expected_open_ports: &HashSet<u16>, max_ports: u16) -> HashSet<u16> {
        let all_ports: HashSet<u16> = (1..=max_ports).collect();
        all_ports.difference(expected_open_ports).cloned().collect()
    }

    fn generate_unique_alerts(&mut self, open_ports: &HashSet<u16>, blocked_ports: &HashSet<u16>) -> Vec<CoreStruts::Log> {
        let mut results = Vec::new();

        for &port in self.expected_open_ports.iter() {
            if !open_ports.contains(&port) && !self.alerted_ports.contains(&port) {
                let msg = format!("Alert: Expected open port {} is closed.", port);
                results.push(CoreStruts::Log::new(CoreEnums::LogType::Serious, self.module_name.clone(), msg));
                self.alerted_ports.insert(port);
                self.previously_closed_ports.insert(port);
            }
        }

        for &port in open_ports.iter() {
            if self.previously_closed_ports.contains(&port) {
                let msg = format!("Alert: Previously closed port {} is now open.", port);
                results.push(CoreStruts::Log::new(CoreEnums::LogType::Serious, self.module_name.clone(), msg));
                self.previously_closed_ports.remove(&port);
            }
        }

        for &port in blocked_ports.iter() {
            if open_ports.contains(&port) && !self.alerted_ports.contains(&port) {
                let msg = format!("Alert: Expected blocked port {} is open.", port);
                results.push(CoreStruts::Log::new(CoreEnums::LogType::Serious, self.module_name.clone(), msg));
                self.alerted_ports.insert(port);
            }
        }

        results
    }

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
    fn get_data(&mut self) -> bool {
        let start_port = self.last_scanned_port + 1;
        let end_port = start_port.saturating_add(500).min(self.max_ports);

        let open_ports = scan_ports_range(start_port..end_port);

        self.current_data = CurrentNetworkData {
            start_port,
            end_port,
            open_ports: open_ports.clone(),
        };

        self.log_scan_results();

        self.last_scanned_port = if end_port == self.max_ports {
            0
        } else {
            end_port
        };

        true
    }

    fn get_testing_data(&mut self) -> bool {
        todo!()
    }

    fn perform_analysis(&mut self) -> Vec<crate::Log> {
        let mut results = Vec::new();

        let open_ports: HashSet<u16> = self.current_data.open_ports.iter().cloned().collect();
        let blocked_ports = Networking::calculate_blocked_ports(&self.expected_open_ports, self.max_ports);

        let alerts = self.generate_unique_alerts(&open_ports, &blocked_ports);

        self.log_generated_alerts(&alerts);

        results.extend(alerts);

        results
    }

    fn get_name(&self) -> String {
        self.module_name.clone()
    }

    fn build_config_fields(&self) -> Vec<crate::ConfigField> {
        vec![
            ConfigField::new("ExpectedOpenPorts".to_owned(), "List of ports that should be open".to_owned(), CoreEnums::ConfigFieldType::Integer, vec!["80".to_owned(), "443".to_owned(), "22".to_owned()], true),
            ConfigField::new("MaxPorts".to_owned(), "Maximum number of ports to scan".to_owned(), CoreEnums::ConfigFieldType::Integer, vec!["65535".to_owned()], false),
        ]
    }

    fn retrieve_config_data(&mut self, data: HashMap<String, Vec<String>>) -> bool {
        for (field, vals) in data {
            match field.as_str() {
                "ExpectedOpenPorts" => {
                    self.expected_open_ports = vals.iter().filter_map(|v| v.parse().ok()).collect();
                }
                "MaxPorts" => {
                    self.max_ports = vals.get(0).and_then(|v| v.parse().ok()).unwrap_or(65535);
                }
                _ => {}
            }
        }
        true
    }
}

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
            max_ports: 65535,
            alerted_ports: HashSet::new(),
            previously_closed_ports: HashSet::new(),
        }
    }
}

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
