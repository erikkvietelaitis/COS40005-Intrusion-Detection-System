use std::vec;

use LaraCore::CoreStruts;
use LaraCore::CoreTraits;
use LaraCore::CoreTraits::AnalysisModule;

use crate::AnalysisModules::*;
use crate::LaraCore::CoreEnums::*;
use crate::LaraCore::CoreStruts::*;
pub mod AnalysisModules;
pub mod LaraCore;

// test from Ben  from his branch

fn main() {
    println!("Welcome to the IDS software");
    //having issues defining an list of all analysis modules
    let mut e_module = AnalysisModules::Example::Example::default();
    // let mut v: [dyn CoreTraits::AnalysisModule;1] = [];
    let mut logs: Vec<Log> = Vec::new();
    let mut i = 0;
    // let mut l = .into_iter();
    while i < 10 {
        e_module.get_data();
        logs = e_module.perform_analysis();
        // Add other modules here
        for l in logs {
            println!("{}", l.build_alert());
        }
        i = i + 1;
    }
}
