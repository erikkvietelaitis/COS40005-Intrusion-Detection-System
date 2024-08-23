use pnet::datalink;
use pnet::packet::ipv4::Ipv4Packet;
use std::collections::HashMap;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

const THRESHOLD: usize = 100; // Number of packets to consider as suspicious
const MONITOR_INTERVAL: Duration = Duration::from_secs(10); // Monitoring interval

// Function to monitor traffic and raise alerts
fn monitor_traffic(packet_counts: Arc<Mutex<HashMap<String, usize>>>) {
    loop {
        thread::sleep(MONITOR_INTERVAL);
        let mut counts = packet_counts.lock().unwrap();

        // Identify suspicious IP addresses
        let suspicious: Vec<String> = counts.iter()
            .filter(|&(_, &count)| count > THRESHOLD)
            .map(|(ip, _)| ip.clone())
            .collect();

        if !suspicious.is_empty() {
            println!("Potential DDoS attack detected. Suspicious IPs:");
            for ip in &suspicious {
                println!("IP: {}", ip);
            }
        }

        // Clear counts for the next monitoring interval
        counts.clear();
    }
}

// Function to capture and process packets
fn capture_packets(packet_counts: Arc<Mutex<HashMap<String, usize>>>) {
    // Get the network interface to monitor
    let interface = datalink::interfaces()
        .into_iter()
        .find(|iface| iface.is_up() && !iface.is_loopback() && iface.ips.iter().any(|ip| ip.is_ipv4()))
        .expect("No suitable network interface found");

    // Create the data link channel
    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(datalink::Channel::Ethernet(_, rx)) => ((), rx),
        Ok(_) => panic!("Unsupported channel type"),
        Err(e) => panic!("Failed to create datalink channel: {:?}", e),
    };

    // Packet capturing loop
    loop {
        match rx.next() {
            Ok(packet) => {
                let packet = Ipv4Packet::new(packet);
                if let Some(ip_packet) = packet {
                    let src_ip = ip_packet.get_source().to_string();
                    let mut counts = packet_counts.lock().unwrap();
                    let entry = counts.entry(src_ip).or_insert(0);
                    *entry += 1;
                }
            },
            Err(e) => println!("Failed to read packet: {:?}", e),
        }
    }
}

fn main() {
    // Create a shared, thread-safe hashmap to store packet counts
    let packet_counts = Arc::new(Mutex::new(HashMap::<String, usize>::new()));

    // Start monitoring traffic in a separate thread
    let packet_counts_clone = packet_counts.clone();
    thread::spawn(move || monitor_traffic(packet_counts_clone));

    // Start capturing packets
    capture_packets(packet_counts);
}
