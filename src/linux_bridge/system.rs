use chrono::Local;
use std::fs::File;
use std::io;
use std::io::*;
use std::str;
use std::thread; //I am aware this is currently not being used, but I am keeping it here for future reference.
use std::thread::*;
use std::time::Duration;
use std::process::Command;
use sysinfo::{Components, Disks, Networks, System};
use nix::unistd::geteuid;

// Function to get and print the current system time
pub fn system_time() -> String {
    let now = Local::now();
    let formatted_time = format!("Current system time: {}", now.format("%H:%M:%S"));
    return formatted_time;
}

//Function to get and print system name "Ubuntu"
pub fn system_name() -> String {
    return System::name().unwrap();
}

// Function to get and print system host name "eriklaptop"
pub fn system_host_name() -> String {
    return System::host_name().unwrap();
}

// Function to get and print system kernel version "5.4.0-42-generic"
pub fn system_kernel_version() -> String {
    return System::kernel_version().unwrap();
}

// Function to get and print system OS version "20.04.1"
pub fn system_os_version() -> String {

    return System::os_version().unwrap();
}


/*
Function to read the content of a file, with a path specified as a parameter, and return the content as a string (content), hence returns an io::Result<String> type.
The file information is stored in the buffer, and the content is read line by line and stored in the content variable.
The function returns the content as a string, and the function breaks if the content cant be read.
*/
pub fn sys_file_read(filepath: &str) -> io::Result<String> {
    let file = File::open(filepath)?;
    let mut reader = BufReader::new(file);
    let mut content = String::new();
    loop {
        let mut buffer = String::new();
        let bytes_read = reader.read_line(&mut buffer)?;

        if bytes_read > 0 {
            content.push_str(&buffer);
        } else {
            break; //Erik use this as part of a more "stable"/"automatic" solution to move away from hardcoding file paths.
        }
    }
    Ok(content)
}

// Used by Erik for testing
// Function to read the content of a file, with a path specified as a parameter, and return the content as a string (content), hence returns an io::Result<String> type.
//This could be modifed to return a Result<String> type, if we wanted to pass through the OK(log_content), as to move the information to another function.
//This could be Result<()> if we dont want to return anything, or you could remove the Result<> and return.
//This file_read() in theory should be able to kept now where ever we want to read a file and off the main function.
pub fn file_read() -> std::io::Result<String> {
    // Declare the path to the file
    let path = "/proc/net/tcp";
    // Read the content of the file
    let log_content = sys_file_read(&path)?;
    // Print the log content
    //I am testing some really spicey code at the moment.
    //I am tryint to see if the code will read in spaces and new lines.
    println!("{}", log_content);
    // Return Ok if the file is read successfully
    return Ok(log_content);
}


// Function to write to a file, with a path and content to a prespecified file path based on another functions declaration.
pub fn sys_file_write(filepath: &str, content: &str) -> io::Result<()> {
    let mut file = File::create(filepath)?;
    file.write_all(content.as_bytes())?;
    Ok(())
}

//Function to write to a file, with a path and content as parameters, and return a Result<()> type.
pub fn file_write() {
     let filepath = "/home/erik/Documents/test.txt";
    let content = "Hello, world!";
     sys_file_write(filepath, content);
}




