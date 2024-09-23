use std::sync::{Arc, Mutex};
use std::collections::{HashMap, HashSet};
use std::thread;
use std::time::{Duration, Instant};
use pnet::datalink;
use pnet::packet::{Packet, ethernet::EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::ip::IpNextHeaderProtocols;

use crate::LaraCore::CoreStruts::Log;
use crate::LaraCore::CoreEnums::LogType;
use crate::LaraCore::CoreEnums::ConfigFieldType;
use crate::ConfigField;
use crate::LaraCore::CoreTraits::AnalysisModule;

/// Struct representing the Packet Sniffer module.
pub struct PacketSniffer {
    pub module_name: String,
    pub interface_name: String,
    pub packets: Arc<Mutex<Vec<PacketData>>>, // Thread-safe storage for packets
    pub packet_threshold: usize, // Alert threshold for packet counts
    pub host_ip: Option<String>, // Host IP to exclude from alerts
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
                    } else if let Some(ipv6) = Ipv6Packet::new(ip_payload) {
                        // Handle IPv6 payloads if necessary (not implemented)
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
            ConfigField::new("HostIP".to_owned(), "Host IP address to be exempted from alerts. Example: 192.168.1.100".to_owned(), ConfigFieldType::String, host_ip, false), // New field
        ]
    }

    fn retrieve_config_data(&mut self, data: HashMap<String, Vec<String>>) -> bool {
        for (field, vals) in data {
            match field.as_str() {
                "InterfaceName[]" => {
                    self.interface_name = vals.get(0).cloned().unwrap_or_default();
                }
                "PacketThreshold" => {
                    self.packet_threshold = vals.get(0)
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(self.packet_threshold);
                }
                "HostIP" => {
                    self.host_ip = vals.get(0).cloned();
                }
                _ => {}
            }
        }
        true
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
        }
    }
}
