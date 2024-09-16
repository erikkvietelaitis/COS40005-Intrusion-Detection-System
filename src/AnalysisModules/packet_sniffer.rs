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

pub struct PacketSniffer {
    pub module_name: String,
    pub interface_name: String,
    pub packets: Arc<Mutex<Vec<PacketData>>>,
    pub packet_threshold: usize,
}

#[derive(Debug, Clone)]
pub struct PacketData {
    pub source_ip: Option<String>,
    pub source_port: Option<u16>,
}

impl PacketSniffer {
    // Creates a new `PacketSniffer` instance.
    // `module_name` - Name of the module.
    // `interface_name` - Name of the network interface to capture packets from.
    // `packet_threshold` - The number of packets that triggers an alert.
    pub fn new(module_name: &str, interface_name: &str, packet_threshold: usize) -> Self {
        Self {
            module_name: module_name.to_string(),
            interface_name: interface_name.to_string(),
            packets: Arc::new(Mutex::new(Vec::new())),
            packet_threshold,
        }
    }

    // Captures packets from the specified network interface for a given duration.
    // `duration` - The amount of time to capture packets.
    fn capture_packets(&self, duration: Duration) {
        let packets = Arc::clone(&self.packets);
        let interface = datalink::interfaces()
            .into_iter()
            .find(|iface| iface.name == self.interface_name)
            .expect("Interface not found");

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

                    let ip_payload = ethernet.payload();

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
                        let next_header = ipv6.get_next_header();
                        // Handle IPv6 payloads if necessary
                    }

                    let mut packets = packets.lock().unwrap();
                    packets.push(packet_data);
                }
                Err(e) => {
                    println!("Error receiving packet: {:?}", e);
                }
            }
        }
    }

    // Analyzes the captured packets and generates logs if the packet count exceeds the threshold.
    // A vector of `Log` instances containing the analysis results.
    fn analyze_packets(&self) -> Vec<Log> {
        let mut results = Vec::new();
        let packets = self.packets.lock().unwrap();
    
        // Use a HashSet to track unique source IP and port combinations
        let mut unique_source_info = HashSet::new();
        for packet in packets.iter() {
            if let Some(source_ip) = &packet.source_ip {
                if let Some(source_port) = packet.source_port {
                    unique_source_info.insert((source_ip.clone(), source_port));
                }
            }
        }
    
        // Alert if packet count exceeds threshold
        if packets.len() > self.packet_threshold {
            let source_info: Vec<String> = unique_source_info.into_iter().map(|(ip, port)| {
                format!("Source IP: {}, Source Port: {}", ip, port)
            }).collect();
    
            results.push(Log::new(
                LogType::Warning,
                self.module_name.clone(),
                format!(
                    "Packet alert: {} packets captured, exceeds threshold of {} packets. {}",
                    packets.len(),
                    self.packet_threshold,
                    source_info.join(", ")
                ),
            ));
        }
    
        results
    }

    // Clears the captured packets from the buffer.
    fn clear_packets(&self) {
        let mut packets = self.packets.lock().unwrap();
        packets.clear();
    }
}

impl AnalysisModule for PacketSniffer {
    // Starts the packet capturing process in a separate thread.
    // `true` if the process was successfully started.
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
        todo!()
    }

    // Performs the packet analysis and returns the generated logs.
    // A vector of `Log` instances containing the analysis results.
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
        let network_interfaces = vec!["eth0".to_owned(), "wlan0".to_owned(), "lo".to_owned()];
        
        // Example packet thresholds
        let packet_thresholds = vec!["10".to_owned(), "50".to_owned(), "200".to_owned()];

        vec![
            ConfigField::new("InterfaceName[]".to_owned(), "Network interface to capture packets from. Example: eth0, wlan0, lo".to_owned(), ConfigFieldType::String, network_interfaces, true),
            ConfigField::new("PacketThreshold".to_owned(), "Number of packets that triggers an alert. Example: 10, 50, 200".to_owned(), ConfigFieldType::Integer, packet_thresholds, true),
        ]
    }

    /// Retrieves and applies configuration data from a `HashMap`.
    /// * `data` - A `HashMap` where keys are configuration field names and values are vectors of configuration values.
    // # Returns
    /// `true` if the configuration was successfully applied.
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
                _ => {}
            }
        }
        true
    }
}

impl Default for PacketSniffer {
    // Provides the default configuration for the `PacketSniffer`.
    // A `PacketSniffer` instance with default values.
    fn default() -> Self {
        Self {
            module_name: String::from("PacketSniffer"),
            interface_name: String::from("eth0"),
            packets: Arc::new(Mutex::new(Vec::new())),
            packet_threshold: 200, // Default threshold changed to 200
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
        }
    }
}
