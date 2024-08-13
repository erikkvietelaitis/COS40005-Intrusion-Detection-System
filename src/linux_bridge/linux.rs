use chrono::Local;
use std::thread::sleep;
use std::time::Duration;

// Function to get and print the current system time
pub fn system_time() {
    loop {
        let now = Local::now();
        println!("Current system time: {}", now);
        sleep(Duration::from_secs(1));
    }
} 