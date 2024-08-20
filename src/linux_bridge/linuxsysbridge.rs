use chrono::Local;
use std::thread;  //I am aware this is currently not being used, but I am keeping it here for future reference.
use std::thread::*;
use std::io;
use std::io::*;
use std::fs::File;
use std::time::Duration;
use sysinfo::{
    System, Components, Disks, Networks 
};

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
/* 
Function to read the content of a file, with a path specified as a parameter, and return the content as a string (content), hence returns an io::Result<String> type.
The file information is stored in the buffer, and the content is read line by line and stored in the content variable.
The function returns the content as a string, and the function breaks if the content cant be read.
*/
pub fn sys_file_read(filepath: &str) -> io::Result<String> { 
    let  file = File::open(filepath)?;
    let mut reader = BufReader::new(file);
    let mut content = String::new();
    loop {
        let mut buffer = String::new();
        let bytes_read = reader.read_line(&mut buffer)?;

        if bytes_read > 0 {
            content.push_str(&buffer);
        } else {
            break;
        }
    }
     Ok(content)
}