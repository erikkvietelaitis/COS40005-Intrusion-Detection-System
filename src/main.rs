use crate::LaraCore::CoreEnums::*;
use crate::LaraCore::CoreStruts::*;
pub mod LaraCore;

// Declare the linux_bridge module
mod linux_bridge;
pub use crate::linux_bridge::{
    linuxsysbridge::*,
    linuxnetbridge::*,
    linuxauthbridge::*,
};

fn main() {
    println!("Welcome to L.A.R.A.!");
       // basic_system_specs();
       // system_name();
       // system_host_name();
       // system_kernel_version();
       // system_os_version();
       // ipadd();
       //system_time();
      let test = file_read();
         //Ok("I am testing some really spicey code at the moment.\nI am tryint to see if the code will read in spaces and new lines.\n")
         //I want to try and fix this so that prints out properly
      print!("{:?}",test);
   }
       




// Function to read the content of a file, with a path specified as a parameter, and return the content as a string (content), hence returns an io::Result<String> type.
//This could be modifed to return a Result<String> type, if we wanted to pass through the OK(log_content), as to move the information to another function.
//This could be Result<()> if we dont want to return anything.
//This file_read() in theory should be able to kept now where ever we want to read a file and off the main function.
fn file_read() -> std::io::Result<String> {
    // Declare the path to the file
       let path = "/home/erik/Documents/test.txt";
    // Read the content of the file
       let log_content = sys_file_read(&path)?; 
    // Print the log content 
    //I am testing some really spicey code at the moment.
    //I am tryint to see if the code will read in spaces and new lines.
    println!("{}", log_content);
    // Return Ok if the file is read successfully
    return Ok(log_content);
} 


