use std::sync::{Arc, Mutex};
use std::collections::{HashMap, HashSet};
use std::thread;
use std::time::{Duration, Instant};
use pnet::datalink;
use pnet::packet::{Packet, ethernet::EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::ip::IpNextHeaderProtocols;

use crate::lara_core::core_structs::Log;
use crate::lara_core::core_enums::LogType;
use crate::lara_core::core_enums::ConfigFieldType;
use crate::ConfigField;
use crate::lara_core::core_traits::AnalysisModule;

/// Struct representing the Packet Sniffer module.
pub struct PacketSniffer {
    pub module_name: String,
    pub interface_name: String,
    pub packets: Arc<Mutex<Vec<PacketData>>>, // Thread-safe storage for packets
    pub packet_threshold: usize, // Alert threshold for packet counts
    pub host_ip: Option<String>, // Host IP to exclude from alerts
    pub has_errors: bool, // Flag to indicate configuration errors
}

/// Struct to hold packet data (source IP and port).
#[derive(Debug, Clone)]
pub struct PacketData {
    pub source_ip: Option<String>,
    pub source_port: Option<u16>,
}

impl PacketSniffer {
    /// Creates a new PacketSniffer instance.
    pub fn new(module_name: &str, interface_name: &str, packet_threshold: usize, host_ip: Option<String>) -> Self {
        Self {
            module_name: module_name.to_string(),
            interface_name: interface_name.to_string(),
            packets: Arc::new(Mutex::new(Vec::new())),
            packet_threshold,
            host_ip,
            has_errors: false, // Initialize error flag
        }
    }

    /// Captures packets for a specified duration.
    fn capture_packets(&self, duration: Duration) {
        let packets = Arc::clone(&self.packets);
        let interface = datalink::interfaces()
            .into_iter()
            .find(|iface| iface.name == self.interface_name)
            .expect("Interface not found");

        // Create a channel to capture packets
        let channel_result = datalink::channel(&interface, Default::default());
        let mut rx = match channel_result {
            Ok(datalink::Channel::Ethernet(_, rx)) => rx,
            _ => panic!("Unsupported channel type"),
        };

        let start_time = Instant::now();
        while Instant::now().duration_since(start_time) < duration {
            match rx.next() {
                Ok(packet) => {
                    let ethernet = EthernetPacket::new(packet).expect("Failed to parse Ethernet packet");
                    let mut packet_data = PacketData {
                        source_ip: None,
                        source_port: None,
                    };

                    // Extract IP payload from Ethernet frame
                    let ip_payload = ethernet.payload();

                    // Handle IPv4 packets
                    if let Some(ipv4) = Ipv4Packet::new(ip_payload) {
                        match ipv4.get_next_level_protocol() {
                            IpNextHeaderProtocols::Tcp => {
                                if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                                    packet_data.source_port = Some(tcp.get_source());
                                }
                            }
                            IpNextHeaderProtocols::Udp => {
                                if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                                    packet_data.source_port = Some(udp.get_source());
                                }
                            }
                            _ => {},
                        }
                        packet_data.source_ip = Some(ipv4.get_source().to_string());
                    }

                    // Store captured packet data
                    let mut packets = packets.lock().unwrap();
                    packets.push(packet_data);
                }
                Err(e) => {
                    println!("Error receiving packet: {:?}", e);
                }
            }
        }
    }

    /// Analyzes captured packets and generates logs for alerts.
    fn analyze_packets(&self) -> Vec<Log> {
        let mut results = Vec::new();
        let packets = self.packets.lock().unwrap();
    
        // Track packet counts by (source IP, source port)
        let mut packet_count_by_ip_port: HashMap<(String, u16), usize> = HashMap::new();
    
        for packet in packets.iter() {
            if let Some(source_ip) = &packet.source_ip {
                // Skip packets from the host IP address
                if let Some(host_ip) = &self.host_ip {
                    if source_ip == host_ip {
                        continue;
                    }
                }
    
                if let Some(source_port) = packet.source_port {
                    // Increment the count for this IP and port
                    let count = packet_count_by_ip_port.entry((source_ip.clone(), source_port)).or_insert(0);
                    *count += 1;
                }
            }
        }
    
        // Generate alerts for IPs and ports that exceed the threshold
        for ((ip, port), count) in packet_count_by_ip_port {
            if count > self.packet_threshold {
                results.push(Log::new(
                    LogType::Warning,
                    self.module_name.clone(),
                    format!(
                        "Packet alert: {} packets captured from Source IP: {} on Port: {} exceeds threshold of {} packets.",
                        count, ip, port, self.packet_threshold
                    ),
                ));
            }
        }
    
        results
    }

    /// Clears the captured packets.
    fn clear_packets(&self) {
        let mut packets = self.packets.lock().unwrap();
        packets.clear();
    }
}

impl AnalysisModule for PacketSniffer {
    fn get_data(&mut self) -> bool {
        if self.has_errors {
            println!("Configuration has errors. PacketSniffer will not run.");
            return false; // Early exit if there are configuration errors
        }

        let duration = Duration::from_secs(5); // Capture packets for 5 seconds
        let sniffer = Arc::new(self.clone());
        let sniffer_clone = Arc::clone(&sniffer);
        thread::spawn(move || {
            sniffer_clone.capture_packets(duration);
        });
        true
    }

    fn get_testing_data(&mut self) -> bool {
        todo!() // Placeholder for testing data
    }

    fn perform_analysis(&mut self) -> Vec<Log> {
        let logs = self.analyze_packets();
        self.clear_packets(); // Clear packets after analysis
        logs
    }

    fn get_name(&self) -> String {
        self.module_name.clone()
    }

    fn build_config_fields(&self) -> Vec<ConfigField> {
        // Example network interfaces
        let network_interfaces = vec!["enp0s3".to_owned(), "wlan0".to_owned(), "eth0".to_owned()];
        
        // Example packet thresholds
        let packet_thresholds = vec!["100".to_owned()];
        
        // Host IP field
        let host_ip: Vec<String> = vec!["192.167.1.100".to_owned()];

        vec![
            ConfigField::new("InterfaceName[]".to_owned(), "Network interface to capture packets from. Example: enp0s3, wlan0, eth0".to_owned(), ConfigFieldType::String, network_interfaces, true),
            ConfigField::new("PacketThreshold".to_owned(), "Number of packets that triggers an alert. Example: 10, 50, 200".to_owned(), ConfigFieldType::Integer, packet_thresholds, true),
            ConfigField::new("HostIP".to_owned(), "Host IP address to be exempted from alerts. Example: 192.168.1.100".to_owned(), ConfigFieldType::String, host_ip, false),
        ]
    }

    fn retrieve_config_data(&mut self, data: HashMap<String, Vec<String>>) -> bool {
        self.has_errors = false; // Reset the error flag
        let mut error_messages = Vec::new(); // Collect error messages

        for (field, vals) in data {
            match field.as_str() {
                "InterfaceName[]" => {
                    self.interface_name = vals.get(0).cloned().unwrap_or_default();
                }
                "PacketThreshold" => {
                    if let Some(v) = vals.get(0) {
                        match v.parse::<usize>() {
                            Ok(threshold) => {
                                self.packet_threshold = threshold;
                            }
                            Err(_) => {
                                error_messages.push(format!("Error: PacketThreshold '{}' is not a valid number.", v));
                                self.has_errors = true; // Set error flag
                            }
                        }
                    } else {
                        error_messages.push("Error: PacketThreshold is missing.".to_string());
                        self.has_errors = true; // Set error flag
                    }
                }
                "HostIP" => {
                    let ip = vals.get(0).cloned();
                    if let Some(ip_value) = &ip {
                        if !ip_value.is_empty() {
                            // Basic IP format check
                            let segments: Vec<&str> = ip_value.split('.').collect();
                            if segments.len() != 4 || segments.iter().any(|&s| s.parse::<u8>().is_err()) {
                                error_messages.push(format!("Error: HostIP '{}' is invalid. It must be a valid IPv4 address.", ip_value));
                                self.has_errors = true; // Set error flag
                            }
                        }
                    }
                    self.host_ip = ip;
                }
                _ => {}
            }
        }

        // Check if the interface name is valid
        let available_interfaces: HashSet<String> = datalink::interfaces()
            .iter()
            .map(|iface| iface.name.clone())
            .collect();

        if !available_interfaces.contains(&self.interface_name) {
            error_messages.push(format!("Error: The specified interface '{}' does not exist.", self.interface_name));
            self.has_errors = true; // Set error flag
        }

        // Print all error messages if there are any
        if self.has_errors {
            for msg in error_messages {
                println!("{}", msg);
            }
            println!("Configuration has errors. Please fix them before starting.");
            return false; // Prevent further execution if invalid
        }

        true // All checks passed
    }
}

impl Default for PacketSniffer {
    fn default() -> Self {
        Self {
            module_name: String::from("PacketSniffer"),
            interface_name: String::from("eth0"),
            packets: Arc::new(Mutex::new(Vec::new())),
            packet_threshold: 100, // Default threshold
            host_ip: None,
            has_errors: false, // Initialize error flag
        }
    }
}

impl Clone for PacketSniffer {
    fn clone(&self) -> Self {
        Self {
            module_name: self.module_name.clone(),
            interface_name: self.interface_name.clone(),
            packets: self.packets.clone(),
            packet_threshold: self.packet_threshold,
            host_ip: self.host_ip.clone(),
            has_errors: self.has_errors, 
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // Helper function to create a test PacketSniffer
    fn create_sniffer() -> PacketSniffer {
        PacketSniffer::new("TestSniffer", "lo", 10, None)
    }

    #[test]
    fn test_packet_sniffer_initialization() {
        let sniffer = create_sniffer();
        assert_eq!(sniffer.module_name, "TestSniffer");
        assert_eq!(sniffer.interface_name, "lo");
        assert_eq!(sniffer.packet_threshold, 10);
        assert!(sniffer.host_ip.is_none());
        assert!(!sniffer.has_errors);
    }

    #[test]
    fn test_capture_packets_empty() {
        let sniffer = create_sniffer();
        sniffer.capture_packets(Duration::from_secs(1)); // Capture for 1 second

        let packets = sniffer.packets.lock().unwrap();
        assert!(packets.is_empty());
    }

    #[test]
    fn test_analyze_packets_no_alerts() {
        let sniffer = create_sniffer();
        let packets = vec![
            PacketData {
                source_ip: Some("192.168.0.1".to_string()),
                source_port: Some(80),
            },
            PacketData {
                source_ip: Some("192.168.0.2".to_string()),
                source_port: Some(80),
            },
        ];

        // Simulate captured packets
        {
            let mut locked_packets = sniffer.packets.lock().unwrap();
            locked_packets.extend(packets);
        }

        let logs = sniffer.analyze_packets();
        assert!(logs.is_empty());
    }

    #[test]
    fn test_analyze_packets_with_alerts() {
        let sniffer = create_sniffer();
        let packets = vec![
            PacketData {
                source_ip: Some("192.168.0.1".to_string()),
                source_port: Some(80),
            },
            PacketData {
                source_ip: Some("192.168.0.1".to_string()),
                source_port: Some(80),
            },
            PacketData {
                source_ip: Some("192.168.0.1".to_string()),
                source_port: Some(80),
            },
        ];

        // Simulate captured packets
        {
            let mut locked_packets = sniffer.packets.lock().unwrap();
            locked_packets.extend(packets);
        }

        let logs = sniffer.analyze_packets();
        assert_eq!(logs.len(), 1);
        assert!(logs[0].build_alert().contains("[Warning]"));
        assert!(logs[0].message.contains("Packet alert: 3 packets captured from Source IP: 192.168.0.1 on Port: 80 exceeds threshold of 10 packets."));
    }
}