use chrono::Local;
use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::io::*;
use ini::Ini;

use std::str;
 //I am aware this is currently not being used, but I am keeping it here for future reference.



use sysinfo::System;

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
pub fn read_csv(path: String) -> io::Result<HashMap<String,HashMap<String,Vec<String>>>>{
    let conf_res = Ini::load_from_file(path);
    let conf = match conf_res{
        Ok(conf) => conf,
        Err(_e) =>  panic!("Malformed config.ini file. Please update document to follow correct formatting"),
    };
    
    let mut config_map: HashMap<String, HashMap<String, Vec<String>>> = HashMap::new();
    let mut sec: HashMap<String, Vec<String>>;
    let mut arr_key:String;
    for (section, properties) in conf.iter() {
        let section_name = section.unwrap_or("default").to_string();
        sec = HashMap::new();
        
        for (key, value) in properties.iter() {
            
            if key.ends_with("[]") {
                arr_key = key.strip_suffix("[]").unwrap_or("undefined").to_owned();
                if sec.contains_key(&arr_key){
                    sec.get_mut(&arr_key).unwrap().push(value.to_owned());
                }else{
                    sec.insert(arr_key,vec![value.to_owned()]);
                }
            } else {
                sec.insert(key.to_string(), vec![value.to_string()]);
            }
        }
        config_map.insert(section_name, sec);

    }
    Ok(config_map)
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

    match sys_file_write(filepath, content) {
        Ok(()) => {
            // Optionally, you can print a success message or log the success
            println!("File written successfully.");
        }
        Err(e) => {
            // Handle the error case, e.g., by logging or printing an error message
            eprintln!("Failed to write file: {}", e);
        }
    }
}



use std::process::Command;
//Function to call CPU usage directly from the top command, and return the CPU usage as a string.
pub fn cpu_usage() -> String {
    let output = Command::new("top")
        .output()
        .expect("Failed to execute command");
    let last = String::from_utf8_lossy(&output.stdout);
    return last.to_string();
}


// //Function to call memory usage from the sysinfo crate, and return the memory usage as a string.
// pub fn memory_usage() -> String {
//     let system = System::new_all();
//     let memory = system.used_memory();
//     return format!("Memory Usage: {} KB", memory);
// }

// //Function to call disk usage from the sysinfo crate, and return the disk usage as a string.
// pub fn disk_usage() -> String {
//     let system = System::new_all();
//     let disk = system.used_memory();
//     return format!("Disk Usage: {} KB", disk);
// }





