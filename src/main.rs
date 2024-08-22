use std::any::type_name;
use std::vec;

use std::{thread, time};
use LaraCore::CoreStruts;
use LaraCore::CoreTraits;
use LaraCore::CoreTraits::AnalysisModule;

use crate::AnalysisModules::*;
use crate::LaraCore::CoreEnums::*;
use crate::LaraCore::CoreStruts::*;
pub mod AnalysisModules;
pub mod LaraCore;

fn main() {
    println!("Chromia loading");
    // Should be loaded by configuration. Higher number means lower performance impact of the IDS
    let tick_intervals = time::Duration::from_millis(1000);
    println!(
        "tick interval set to {} milliseconds",
        tick_intervals.as_millis()
    );
    //having issues defining an list of all analysis modules
    let mut modules: Vec<Box<dyn AnalysisModule>>;
    modules = vec![Box::new(
        <AnalysisModules::example::Example as std::default::Default>::default(),
    )];

    println!("Successfully loaded {} module/s", modules.len().to_string());
    let mut logs: Vec<Log> = Vec::new();
    let mut i = 0;
    loop {
        println!("Starting Tick({})", i.to_string());
        for module in modules.iter_mut() {
            module.get_data();
            logs.append(&mut module.perform_analysis());
        }
        println!("Following logs were generated this tick:");
        for log in logs.iter() {
            println!("{}", log.build_alert());
        }
        logs = Vec::new();
        i += 1;
        thread::sleep(tick_intervals)
    }
}
