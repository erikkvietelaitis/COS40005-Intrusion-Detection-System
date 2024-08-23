use std::io::{self, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;
use std::collections::HashSet;

fn scan_port(ip: &str, port: u16) -> bool {
    let address = format!("{}:{}", ip, port);
    let socket: SocketAddr = address.parse().unwrap();

    match TcpStream::connect_timeout(&socket, Duration::from_secs(1)) {
        Ok(_) => true,
        Err(_) => false,
    }
}

fn is_vulnerable_port(port: u16) -> bool {
    let vulnerable_ports: HashSet<u16> = vec![21, 22, 23, 25, 80, 443, 3389].into_iter().collect();
    vulnerable_ports.contains(&port)
}

fn main() {
    print!("Enter the IP address to scan: ");
    io::stdout().flush().unwrap();

    let mut ip = String::new();
    io::stdin().read_line(&mut ip).unwrap();
    let ip = ip.trim();  // Remove newline character

    let start_port: u16 = 1;
    let end_port: u16 = 1024;

    println!("Scanning ports on {} from {} to {}...", ip, start_port, end_port);

    for port in start_port..=end_port {
        if scan_port(ip, port) {
            println!("Port {} is open", port);
            if is_vulnerable_port(port) {
                println!("ALERT: Vulnerable port {} is open!", port);
            }
        } else {
            println!("Port {} is closed", port);
        }
    }

    println!("Port scan complete.");
}
