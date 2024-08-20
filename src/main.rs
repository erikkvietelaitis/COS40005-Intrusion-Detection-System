use crate::LaraCore::CoreEnums::*;
use crate::LaraCore::CoreStruts::*;
pub mod LaraCore;

// Declare the linux_bridge module
mod linux_bridge;
pub use crate::linux_bridge::{
    linuxsysbridge::*,
    linuxnetbridge::*,
};

fn main() {
    println!("Welcome to L.A.R.A.!");
   // basic_system_specs();
    system_time(); // Call the system_time function from the linux module
}

