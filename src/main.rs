use std::any::type_name;
use std::vec;
use serde_json;
use std::{thread, time};
use LaraCore::CoreTraits::AnalysisModule;

use crate::LaraCore::CoreStruts::*;
pub mod AnalysisModules;
use crate::linux_bridge::*;
pub mod LaraCore;
pub mod linux_bridge;
use ini::Ini;
use std::collections::HashMap;

// Declare the linux_bridge module

fn main() {
    let conf = Ini::load_from_file("config.ini").unwrap();
    
    let mut config_map: HashMap<String, Vec<String>> = HashMap::new();

    for (section, properties) in conf.iter() {
        let section_name = section.unwrap_or("default").to_string();
        
        for (key, value) in properties.iter() {
            if key.ends_with("[]") {
                let array_key = format!("{}.{}", section_name, &key[0..key.len()-2]);
                let values: Vec<String> = value.split(',').map(|s| s.trim().to_string()).collect();
                config_map.insert(array_key, values);
            } else {
                config_map.insert(format!("{}.{}", section_name, key), vec![value.to_string()]);
            }
        }
    }
    println!("{:?}", serde_json::to_string(&config_map).unwrap());
    // Example of accessing array values
    if let Some(array) = config_map.get("section_name.array_key") {
    }
}
