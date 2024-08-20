use chrono::Local;
use std::thread::sleep;
use std::time::Duration;


// Function to get and print the current system time
pub fn system_time() {
    loop {
        let now = Local::now();
        let formatted_time = format!(
            "Current system time: {}",
            now.format("%H:%M:%S")
        );
        println!("{}", formatted_time);
        sleep(Duration::from_secs(1));
    }
}




