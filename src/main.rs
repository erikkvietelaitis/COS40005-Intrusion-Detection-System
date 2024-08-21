use std::vec;

use LaraCore::CoreStruts;
use LaraCore::CoreTraits;
use LaraCore::CoreTraits::AnalysisModule;
use std::{thread, time};

use crate::AnalysisModules::*;
use crate::LaraCore::CoreEnums::*;
use crate::LaraCore::CoreStruts::*;
pub mod AnalysisModules;
pub mod LaraCore;


fn main() {
    println!("Chromia loading");
    // Should be loaded by configuration. Higher number means lower performance impact of the IDS
    let tick_intervals = time::Duration::from_millis(1000);    
    println!("tick interval set to {} milliseconds", tick_intervals.as_millis());
    //having issues defining an list of all analysis modules
    let mut modules: Vec<Box<dyn AnalysisModule>>;
    modules = vec![Box::new(
        <AnalysisModules::Example::Example as std::default::Default>::default(),
    )];
    println!("Successfully built ");
    let mut logs: Vec<Log> = Vec::new();
    let mut i = 0;
    // loop{
        

    //     thread::sleep(tick_intervals);
    // }
    // while i < 10 {
    //     e_module.get_data();
    //     logs = e_module.perform_analysis();
    //     // Add other modules here
    //     for l in logs {
    //         println!("{}", l.build_alert());
    //     }
    //     i = i + 1;
    // }
}
