use clap::Parser;
use std::collections::HashMap;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::vec;

use lara_core::core_traits::AnalysisModule;
use std::{thread, time};

use crate::lara_core::core_structs::*;
pub mod analysis_modules;
use crate::linux_bridge::*;
pub mod lara_core;
pub mod linux_bridge;

// Declare the linux_bridge module
#[derive(Parser)]
struct Args {
    /// Activate debug mode
    #[arg(short, long, action)]
    debug: bool,
}
fn main() {
    let mut debug = false;
    let args = Args::parse();
    if (args.debug) {
        debug = true;
    }
    // TODO: Put startup info in seperate function
    println!("Chromia({}) is starting", env!("CARGO_PKG_VERSION"));
    println!("------------------");
    if debug {
        println!("========== Host System Info: ==========");
        println!("> Host Name :{}", system::system_host_name());
        println!("> OS: {}", system::system_name());
        println!("> OS version: {}", system::system_os_version());
        println!("> Kernal version: {}", system::system_kernel_version());
        println!("> Current Time: {}", system::system_time());
        println!("=======================================");
        println!("Initializing Core systems:");
    }

    println!("");
    if debug {
        println!("Initializing Analysis Modules:");
        println!("");
    }
    let mut modules: Vec<Box<dyn AnalysisModule>>;
    // ADD NEW MODULES HERE \|/ use example module's exact structure
    modules = vec![
        Box::new(<analysis_modules::example::Example as std::default::Default>::default()),
        Box::new(<analysis_modules::anomaly_detection::AnomalyDetector as std::default::Default>::default()),
        Box::new(<analysis_modules::fim::FIM as std::default::Default>::default()),
        Box::new(<analysis_modules::network::Networking as std::default::Default>::default()),
        Box::new(<analysis_modules::authentication::Authentication as std::default::Default>::default()),
        Box::new(<analysis_modules::packet_sniffer::PacketSniffer as std::default::Default>::default()),
        Box::new(<analysis_modules::httpserver::HTTPServer as std::default::Default>::default())
    ];
    println!("    loaded {} module/s", modules.len().to_string());

    if !Path::new("/etc/Chromia/config.ini").exists() {
        create_config(modules);
        return;
    }

    let config_result: Result<HashMap<String, HashMap<String, Vec<String>>>, std::io::Error> =
        system::read_csv("/etc/Chromia/config.ini".to_owned());
    let config = match config_result {
        Ok(file) => file,
        Err(error) => panic!("Problem opening the file: {error:?}"),
    };
    println!("Successfully found config file!");
    // load core info
    let mut core_fields_default: HashMap<String, Vec<String>> = HashMap::new();
    core_fields_default["tickInterval"] = vec!["1000".to_owned()];
    core_fields_default["logLocation"] = vec!["/var/log/Chormia.log".to_owned()];

    let core_fields: HashMap<String, Vec<String>> = match config.get("CoreSystem") {
        Some(s) => s.clone(),
        None => core_fields_default.clone(),
    };
    let tick_interval_str = core_fields
        .get("tickInterval")
        .unwrap_or(core_fields_default.get("tickInterval").unwrap());

    let tick_intervals = time::Duration::from_millis(
        Some(tick_interval_str.parse::<i32>()).unwrap_or(
            core_fields_default
                .get("tickInterval")
                .unwrap()
                .parse::<i32>(),
        ),
    );
    let log_dir =  Path::new(core_fields.get("logLocation").unwrap_or(core_fields_default.get("logLocation").unwrap()));
    if log_dir.exists() {
        println!("Log File found at dir '{}'",log_dir);
    } else {
        println!("Log File dir '{}' does not exist, creating now.", log_dir);
        match File::create(path) {
            Ok(mut file) => {
                println!("Log file at '{}' created successfully.", log_dir);
            }
            Err(err) => {
                eprintln!("Error creating log '{}': {:?}", log_dir, err);
                return Err(err); 
            }
        }
    }
    // Should be loaded by configuration. Higher number means lower performance impact of the IDS
    println!("Tick Interval: {}ms", tick_intervals.as_millis());
    modules.retain_mut(| module|{
        let section: HashMap<String, Vec<String>>;

        section = match config.get(&module.get_name()) {
            Some(s) => s.clone(),
            None => section_not_found(module.get_name()),
        };
        if !module.retrieve_config_data(section){
            println!("{} could not be started due to an error in the config file! Please review errors and restart Chromia",module.get_name());
            return false;
        }else{
            return true;
        }
    });

    let mut logs: Vec<Log> = Vec::new();
    let mut i = 0;
    println!("STARTUP SUCCESSFULL CHROMIA IS NOW ON LOOKOUT!!");
    println!("------------------(Real Time alerts)------------------");

    loop {
        if debug {
            println!("Starting Tick({})", i.to_string());
        }
        for module in modules.iter_mut() {
            if module.get_data() {
                if debug {
                    println!("Module:'{}' successfully gathered data", module.get_name());
                }
            } else {
                if debug {
                    println!(
                        "ERROR::Module:'{}' failed trying to collect data",
                        module.get_name()
                    );
                }
            }
            logs.append(&mut module.perform_analysis());
        }
        if debug {
            println!("Following logs were generated this tick:");
        }
        for log in logs.iter() {
            if debug {
                println!("{}", log.build_alert());
            }
            let _ = append_to_log(&log.build_alert(),log_dir);
        }
        logs = Vec::new();
        i += 1;
        thread::sleep(tick_intervals)
    }
}
fn section_not_found(name: String) -> HashMap<String, Vec<String>> {
    println!(
        "Config for {} module was not found! Chromia will attempt to use default values",
        name
    );
    return HashMap::new();
}

fn create_config(mut modules: Vec<Box<dyn AnalysisModule>>) {
    println!("Could not find config file; Creating configuration file now");
    let mut config_file_contents: String = String::new();
    let mut fields: Vec<ConfigField>;
    //Define core system fields
    config_file_contents.push_str("[CoreSystem]\n;The time in milliseconds that the systems waits between checks \n;Higher numbers reduce performance impact and timeliness of alerts\ntickInterval=1000\n;Location to write log file\nlogLocation");
    for module in modules.iter_mut() {
        config_file_contents.push_str("[");
        config_file_contents.push_str(&module.get_name());
        config_file_contents.push_str("]");

        fields = module.build_config_fields();
        for field in fields.into_iter() {
            config_file_contents.push_str(&field.build_field());
        }
        config_file_contents.push_str("\n");
    }
    let path = Path::new("/etc/Chromia");
    if !path.exists() {
        match fs::create_dir_all(path) {
            Ok(_) => println!(""),
            Err(e) => println!("Failed to create directory: {}", e),
        }
    }

    let file_result = system::sys_file_write("/etc/Chromia/config.ini", &config_file_contents);
    match file_result{
        Ok(_) => println!("Successfully created Config file.\n Please fill out file and re-run Chromia to activate"),
        Err(_e) => panic!("Could not create file in current directory! (Does Chromia have write permissions?)"),
    }
    return;
}
fn append_to_log(message: &str, log_dir: Path) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .append(true)
        .create(true) // This will create the file if it doesn't exist
        .open(log_dir)?;

    writeln!(file, "{}", message)?; // Write the message and append a newline
    Ok(())
}
