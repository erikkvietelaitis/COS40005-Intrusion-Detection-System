use clap::Parser;
use std::collections::HashMap;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::time::Duration;
use std::vec;
use std::fs::File;
use lara_core::core_traits::AnalysisModule;
use std::{thread, time};

use crate::lara_core::core_structs::*;
pub mod analysis_modules;
use crate::linux_bridge::*;
pub mod lara_core;
pub mod linux_bridge;
// for tpm tie-in
use std::process::{self};
use std::process::{Command,Stdio};
use std::str;
use std::io;

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

    
    let tpm_folder_a = "/var/chromia";
    let tpm_folder_p = "/var/chromia/ids";
    let ids_bootlogpath = Path::new("/var/log/ironids.log");
    let _ = append_to_log(&tpm_folder_a,ids_bootlogpath);
    let fpath = Path::new(tpm_folder_a);
    if !fpath.exists() {
        // Create the folder
        match fs::create_dir(fpath) {
            Ok(_) => {
                append_to_log(&format!("Directory created successfully."),ids_bootlogpath);
                let fpath2 = Path::new(tpm_folder_p);
                match fs::create_dir(fpath2) {
                    Ok(_) => {
                        append_to_log(&format!("Directory created successfully."),ids_bootlogpath);
                    }
                    Err(e) => {append_to_log(&format!("Failed to create directory: {}", e),ids_bootlogpath).expect("directory creation to succeed")}
                }
            }
            Err(e) => {append_to_log(&format!("Failed to create directory: {}", e),ids_bootlogpath);}
        }
    } else {
        println!("Folder already exists.");
        let fpath = Path::new(tpm_folder_p);
        if !fpath.exists() {
            // Create the folder
            match fs::create_dir(fpath) {
                Ok(_) => {
                    append_to_log(&format!("Directory created successfully."),ids_bootlogpath);
                    let fpath2 = Path::new(tpm_folder_p);
                    match fs::create_dir(fpath2) {
                        Ok(_) => {
                            append_to_log(&format!("Directory created successfully."),ids_bootlogpath);
                        }
                        Err(e) => {append_to_log(&format!("Failed to create directory: {}", e),ids_bootlogpath).expect("directory creation to succeed")}
                    }
                }
                Err(e) => {append_to_log(&format!("Failed to create directory: {}", e),ids_bootlogpath);}
            }
        } else {
            append_to_log(&format!("Folder already exists."),ids_bootlogpath);
            
        }
    }

    let tick = time::Duration::from_millis(1000);
    let debug = false;
    let target_pid = process::id();
    let lock_path = format!("/var/chromia/ids/{}",target_pid.to_string());
    append_to_log(&format!("{}",lock_path.to_string()),ids_bootlogpath); //debug use

    // 1 - see if any remnants exist
    let (lca, lcb) = lock_check(&target_pid);

    if !lca {
        append_to_log(&format!("Previous shutdown improper!! ID of {} was found", lcb),ids_bootlogpath);
    } else {
        let _ = File::create(&lock_path);
        if file_check(&lock_path) {
            append_to_log(&format!("Lock file created."),ids_bootlogpath); // to log
        }
    }

    
 
    
    // confirm hash of TPM code
    let tpm_path = "/bin/Chromia/ctpb_tpm";
   
    let (bbo, exec_hash) = genhash(&tpm_path);
    if bbo {
        append_to_log(&format!("Hash: '{}'", exec_hash.trim()),ids_bootlogpath);
        if exec_hash.trim() == "4e0c3c94b1d2f7686a7115fcc74d80d5303874d86174ca3805972e2c99a7b799".to_string() {
            append_to_log(&format!("No tamper found for TPM."),ids_bootlogpath);
        } else {
            append_to_log(&format!("Hash for TPM not matching."),ids_bootlogpath);
        }
    }

    println!("");
    if debug {
        println!("Initializing Analysis Modules:");
        println!("");
    }
    let mut modules: Vec<Box<dyn AnalysisModule>>;
    // ADD NEW MODULES HERE \|/ use example module's exact structure
    modules = vec![
        
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
    core_fields_default.insert("tickInterval".to_owned(),vec!["1000".to_owned()]);
    core_fields_default.insert("logLocation".to_owned(), vec!["/var/log/Chormia.log".to_owned()]);

    let core_fields: HashMap<String, Vec<String>> = match config.get("CoreSystem") {
        Some(s) => s.clone(),
        None => core_fields_default.clone(),
    };
    let tick_interval_str = core_fields
        .get("tickInterval")
        .unwrap_or(core_fields_default.get("tickInterval").unwrap());

    let binding = tick_interval_str[0].parse::<u64>();
    let tick_int_u = match &binding{
        Ok(number) => number,
        Err(_) => &1000
    };
    let tick_intervals = Duration::from_millis(*tick_int_u);
    let log_dir_str = core_fields.get("logLocation").unwrap_or(core_fields_default.get("logLocation").unwrap());
    let log_dir =  Path::new(&log_dir_str[0]);
    if log_dir.exists() {
        println!("Log File found at dir '{}'",log_dir_str[0]);
    } else {
        println!("Log File dir '{}' does not exist, creating now.", log_dir_str[0]);
        match File::create(log_dir_str[0].clone()) {
            Ok(mut file) => {
                println!("Log file at '{}' created successfully.", log_dir_str[0]);
            }
            Err(err) => {
                eprintln!("Error creating log '{}': {:?}", log_dir_str[0], err);
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
            let _ = append_to_log(&log.build_alert(),&log_dir);
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
    config_file_contents.push_str("[CoreSystem]\n;The time in milliseconds that the systems waits between checks \n;Higher numbers reduce performance impact and timeliness of alerts\ntickInterval=1000\n;Location to write log file\nlogLocation=/var/log/Chormia.log\n");
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
fn append_to_log(message: &str, log_dir: &Path) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .append(true)
        .create(true) // This will create the file if it doesn't exist
        .open(log_dir)?;

    writeln!(file, "{}", message)?; // Write the message and append a newline
    Ok(())
}
fn lock_check(target_pid: &u32) -> (bool, u32) {
    let lock_name = directory_read("/var/chromia/ids").unwrap_or_else(|| "aa".to_string());
    let lock_pid: u32 = lock_name.parse().unwrap_or(0);
    if lock_pid == 0 {
        return (true, 0);
    } else if lock_pid == *target_pid {
        return (true, *target_pid);
    } else {
        return (false, lock_pid);
    }
}
fn genhash(key: &str) -> (bool, String) {
    let ids_bootlogpath = Path::new("/var/log/ironids.log");
    let _ = append_to_log(&ids_bootlogpath,ids_bootlogpath);
    let output = match Command::new("/bin/Chromia/Data/b3sum")
        .arg(key)
        .arg("--no-names")
        .output() {
        
        Ok(output) => output,
        Err(err) => {
            append_to_log(&format!("Failed to execute command for key '{}': {}", key, err),ids_bootlogpath);
            return (false, String::new());
        }
    };
    // Convert output to string
    let stdout_str = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr_str = String::from_utf8_lossy(&output.stderr).into_owned();
    
    //println!("{}", stdout_str);

    if !stderr_str.is_empty() {
        append_to_log(&format!("stderr for key '{}': {}", key, stderr_str),ids_bootlogpath);
    }

    (true, stdout_str)
}
fn directory_read(path: &str) -> Option<String> {
    let entries = fs::read_dir(path).ok()?;

    if let Some(entry) = entries.into_iter().next() {
        let entry = entry.ok()?;
        let path = entry.path();

        if path.is_file() {
            if let Some(name_str) = path.file_name().and_then(|name| name.to_str()) {
                return Some(name_str.to_string());
            }
        }
    }

    None
}
fn file_check(path: &str) -> bool {
    Path::new(path).exists()
}