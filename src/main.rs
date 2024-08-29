use std::any::type_name;
use std::vec;
use std::path::Path;

use std::{thread, time};
//use system::{system_uptime, system_user};
use LaraCore::CoreTraits::AnalysisModule;

use crate::LaraCore::CoreStruts::*;
pub mod AnalysisModules;
use crate::linux_bridge::system;
use crate::linux_bridge::auth::*;
pub mod LaraCore;
pub mod linux_bridge;

// Declare the linux_bridge module

fn main() {
    // TODO: Put startup info in seperate function
    println!("Chromia({}) is starting", env!("CARGO_PKG_VERSION"));
    println!("------------------");
    println!("Host System Info:");
    println!("    Host Name :{}", system::system_host_name());
    println!("    OS: {}", system::system_name());
    println!("    OS version: {}", system::system_os_version());
    println!("    Kernal version: {}", system::system_kernel_version());
    println!("    Current Time: {}", system::system_time());
    println!("");
    println!("Initialising Core systems:");
    if  !Path::new("config").exists(){
        
        return;
    }
    // Should be loaded by configuration. Higher number means lower performance impact of the IDS
    let tick_intervals = time::Duration::from_millis(1000);
    println!("    tick interval: {}ms", tick_intervals.as_millis());
    println!("");

    // println!("Initialising Analysis Modules:");
    // let mut modules: Vec<Box<dyn AnalysisModule>>;
    // println!("");
    // // ADD NEW MODULES HERE \|/ use example module's exact structure
    // modules = vec![
    //     Box::new(<AnalysisModules::example::Example as std::default::Default>::default()),
    // ];
    // println!("    loaded {} module/s", modules.len().to_string());
    // let mut logs: Vec<Log> = Vec::new();
    // let mut i = 0;
    // println!("STARTUP SUCCESSFULL CHROMIA IS NOW ON LOOKOUT");
    // println!("------------------(Real Time alerts)------------------");

    // loop {
    //     println!("Starting Tick({})", i.to_string());
    //     for module in modules.iter_mut() {
    //         if (module.get_data()) {
    //             println!("Module:'{}' succesfulled gathered data", module.get_name());
    //         } else {
    //             println!(
    //                 "ERROR::Module:'{}' failed trying to collect data",
    //                 module.get_name()
    //             );
    //         }
    //         logs.append(&mut module.perform_analysis());
    //     }
    //     println!("Following logs were generated this tick:");
    //     for log in logs.iter() {
    //         println!("    {}", log.build_alert());
    //     }
    //     logs = Vec::new();
    //     i += 1;
    //     thread::sleep(tick_intervals)
    // }
    
    println!("Hello, world!");
    let test = btmp_dump();
    println!("{}", test);
}
