use chrono::Local;
//use std::io::BufReader;
use std::thread::sleep;
use std::time::Duration;
use sysinfo::{
    System, Components, Disks, Networks, 
};
use std::fs::File;
use std::io::{self, BufRead, BufReader};
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
// Function to get and print system name "Ubuntu"
pub fn system_name(){
let system_name: String = System::name().unwrap();
println!("{}",system_name);
}
// Function to get and print system host name "eriklaptop"
pub fn system_host_name(){
let system_host_name: String = System::host_name().unwrap();
println!("{}",system_host_name);
}
// Function to get and print system kernel version "5.4.0-42-generic"
pub fn system_kernel_version(){
let system_kernel: String = System::kernel_version().unwrap();
print!("{}",system_kernel);
}
// Function to get and print system OS version "20.04.1"
pub fn system_os_version(){
    let system_os_version: String = System::os_version().unwrap();
   print!("{}", system_os_version);
    }

//Basic:: Hard Coded file reading 
pub fn file_read() -> io::Result<()>{
let filepath = "/home/erik/Documents/test.txt";
let file = File::open(filepath)?;
let reader = BufReader::new(file);
    for line in reader.lines(){
        let line = line?;
        println!("{}", line)
    }
    Ok(())
}