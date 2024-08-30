use std::collections::HashMap;

use crate::LaraCore::CoreStruts::*;

pub trait AnalysisModule {
    /**
     * Use this function to gather data from linux systems. Return true unless error occurred
     */
    fn get_data(&mut self) -> bool;
    /**
     * generate testing data. This function should NOT interact with linux, merely just generate fake data.
     */
    fn get_testing_data(&mut self) -> bool;
    /**
     * This analyses the most recent set of data and returns logs to be logged.
     */
    fn perform_analysis(&mut self) -> Vec<Log>;
    /**
     *
     */
    fn get_name(&self) -> String;

    fn build_config_fields(&self) -> Vec<ConfigField>;
    fn insert_config_data(&self, data: HashMap<String, Vec<String>>) -> bool;
}
