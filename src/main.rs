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
       // system_name();
       // system_host_name();
       // system_kernel_version();
       // system_os_version();
       // ipadd();
       // system_time();
}


