use std::collections::HashMap;
use std::fs;
use std::path::Path;
use colored::Colorize;
use core_enums::LogType;
    
use crate::lara_core::*;
use crate::ConfigField;
use crate::Log;
use core_traits::AnalysisModule;
use rand::Rng;


// define the set of data that will be captured each tick, You can structure this however you like to fit your needs, Just call it this name
struct CurrentData {
    logs:HashMap<String, (usize, String)>,
    veclogs: Vec<WebLog>,
}
struct WebLog {
    ip:String,
    msg:String,
    suspicion:String,
}
pub struct HTTPServer {
    // This is the data generated by gatherData in current tick, it will be erased by the next tick
    current_data: CurrentData,
    //Everything else is persistent memory. The data you set in these will be remembered between ticks
    lasterrorlen:usize,
    lastaccesslen:usize,
    errorinitial:bool,
    accessinitial:bool,
    clients: HashMap<String, usize>,
    module_name: String,
    access_path:String,
    error_path:String,

}

impl AnalysisModule for HTTPServer{
    // Use this to gather data from the host computer and store it in the current data struct,
    // This is called at the start of a tick to gather the data into CurrentData struct. If there is an error return false
    fn get_data(&mut self) -> bool {
        self.current_data.logs = HashMap::new();
        if(!Path::new(&self.access_path).exists()){
            eprint!("Could not find Appache Access log file. Provided URI is'{}'. Chromia will still run",&self.error_path);
        }
        if(!Path::new(&&self.error_path).exists()){
            eprint!("Could not find Appache Error log file. Provided URI is'{}'",&self.error_path);
        }
        let errordump:String = fs::read_to_string(&self.error_path).expect("Should have been able to read the file");
        let accessdump:String = fs::read_to_string(&self.access_path).expect("Should have been able to read the file");
        let errorlines: Vec<&str> = errordump.lines().collect();
        let accesslines: Vec<&str> = accessdump.lines().collect();
        let accesslineslen: usize = accesslines.len();
        let errorlineslen: usize = errorlines.len();
        let mut elines: Vec<&str> = vec![];
        let mut alines: Vec<&str> = vec![]; 
        if(!self.accessinitial&&accesslineslen>0)
        {
            self.lastaccesslen = accesslineslen;
            self.accessinitial =true;
        }
        if(!self.errorinitial&&errorlineslen>0)
        {
            self.lasterrorlen = errorlineslen;
            self.errorinitial = true;
        }
        if accesslineslen > 0{
            let mut newalinecount:usize = accesslineslen - self.lastaccesslen;
            while newalinecount > 0{
                alines.push(accesslines[accesslineslen - newalinecount]);
                newalinecount = newalinecount - 1; 
            }
        }
        if errorlineslen > 0{
            let mut newelinecount:usize = errorlineslen - self.lasterrorlen;
            while newelinecount > 0{
                elines.push(errorlines[errorlineslen - newelinecount]);
                newelinecount = newelinecount - 1;
            }
        }
        let mut nl: &str;
        let mut i1: usize = 0;
        self.lastaccesslen = accesslineslen;
        self.lasterrorlen = errorlineslen;
        while i1 < elines.len(){
            nl = elines[i1];
            let nls: Vec<&str> = nl.split(&[']','[']).filter(|&r| r != "").collect();
            if nls[2].contains("php:error") || nls[2].contains("core:error"){
                let errorsplit: Vec<&str> = nl.split(nls[6]).collect();
                    
                let mut nlerrormsg:String = errorsplit[1].to_string();
                nlerrormsg.remove(0);
                let mut data:HashMap<String,String> = HashMap::new();
                data.insert("msg".to_string(),nlerrormsg.clone());
                data.insert("suspicion".to_string(),"1".to_string());
                if nls[6].contains("::1"){
                    let nlip:&str = "::1";
                    self.current_data.logs.insert(nlip.to_string(),(15,format!("Apache error occurred: '{}'",nlerrormsg.clone())));
                }else{
                    let ipsplit: Vec<&str> = nls[6].split(&[' ',':']).filter(|&r| r != "").collect();
                    let nlip:&str = ipsplit[1];
                    self.current_data.logs.insert(nlip.to_string(),(15,format!("Apache error occurred: '{}'",nlerrormsg.clone())));
                }
            }
            i1 = i1 + 1;
        }
        let mut i2: usize = 0;
        while i2 < alines.len(){
            nl = alines[i2];
            let nls: Vec<&str> = nl.split("\"").collect();
            let ipsplit: Vec<&str> = nls[0].split_whitespace().collect();
            let nlip:&str = ipsplit[0];
            let codesplit: Vec<&str> = nls[2].split_whitespace().collect();
            let nlcode:&str = codesplit[0];
            let nlrequest:&str = nls[1];
            let mut msg:String = String::from("request: ".to_string());
            msg.push_str(nlrequest);
            msg.push_str(" code: ");
            msg.push_str(nlcode);
            let mut suspicion:usize = 0;
            if nlcode == "400"{
                suspicion = 20;
                msg.push_str(" Bad Request"); // 20
            }else if nlcode == "401"{
                suspicion = 2700; // 10
                msg.push_str(" Unauthorized");
            }else if nlcode == "403"{
                suspicion = 3000;
                msg.push_str(" Forbidden");
            }else if nlcode == "404"{
                suspicion = 200;
                msg.push_str(" Not Found");
            }else if nlcode == "405"{
                suspicion = 3000;
                msg.push_str(" Method Not Allowed");
            }else if nlcode == "406"{
                suspicion = 15;
                msg.push_str(" Not Acceptable");
            }else if nlcode == "407"{
                suspicion = 3000;
                msg.push_str(" Proxy Authentication Required");
            }else if nlcode == "408"{
                suspicion = 2000;
                msg.push_str(" Request Timeout");
            }else if nlcode == "409"{
                suspicion = 2000;
                msg.push_str(" Conflict");
            }else if nlcode == "410"{
                suspicion = 20;
                msg.push_str(" Gone");
            }else if nlcode == "411"{
                suspicion = 20;
                msg.push_str(" Length Required");
            }else if nlcode == "412"{
                suspicion = 300;
                msg.push_str(" Precondition Failed");
            }else if nlcode == "413"{
                suspicion = 3000;
                msg.push_str(" Payload Too Large");
            }else if nlcode == "414"{
                suspicion = 700;
                msg.push_str(" URI Too Long");
            }else if nlcode == "415"{
                suspicion = 2500;
                msg.push_str(" Unsupported Media Type");
            }else if nlcode == "416"{
                suspicion = 600;
                msg.push_str(" Range Not Satisfiable");
            }else if nlcode == "417"{
                suspicion = 900;
                msg.push_str(" Expectation Failed");
            }else if nlcode == "418"{
                suspicion = 0;
                msg.push_str(" Im a teapot");//shockingly this is a real code
            }else if nlcode == "421"{
                suspicion = 200;
                msg.push_str(" Misdirected Request");
            }else if nlcode == "422"{
                suspicion = 1200;
                msg.push_str(" Unprocessable Content");
            }else if nlcode == "429"{
                suspicion = 3500;
                msg.push_str(" Too Many Requests");
            }else if nlcode == "431"{
                suspicion = 2500;
                msg.push_str(" Request Header Fields Too Large");
            }else if nlcode == "500"{
                suspicion = 2500;
                msg.push_str(" Internal Server Error");
            }else if nlcode == "501"{
                suspicion = 900;
                msg.push_str(" Not Implemented");
            }else if nlcode == "502"{
                suspicion = 2800;
                msg.push_str(" Bad Gateway")
            }else if nlcode == "503"{
                suspicion = 2500;
                msg.push_str(" Service Unavailable");
            }else if nlcode == "504"{
                suspicion = 400;
                msg.push_str(" Gateway Timeout");
            }else if nlcode == "505"{
                suspicion = 400;
                msg.push_str(" HTTP Version Not Supported");
            }else if nlcode == "506"{
                suspicion = 0;
                msg.push_str(" Variant Also Negotiates");
            }else if nlcode == "507"{
                suspicion = 4000;
                msg.push_str(" Insufficient Storage");
            }else if nlcode == "508"{
                suspicion = 2500;
                msg.push_str(" Loop Detected");
            }else if nlcode == "510"{
                suspicion = 400;
                msg.push_str(" Not Extended");
            }else if nlcode == "511"{
                suspicion = 400;
                msg.push_str(" Network Authentication Required");
            }
            
            self.current_data.logs.insert(nlip.to_string(),(suspicion,msg.clone()));
            i2 = i2 + 1;
        }
        return true;
    }
    // Can leave this for todo until testing. It should do the same as get data, but return a consistent predictable 
    // dataset to current data. It will be used for unit testing
    fn get_testing_data(&mut self) -> bool {
        todo!()
    }
    // Take the current data gathered from one of the functions above, using this data, 
    // plus the persistent data stored in the object to create logs (AKA alerts) 
    fn perform_analysis(&mut self) -> Vec<crate::Log> {
        let mut results: Vec<core_structs::Log> = Vec::new();
        let self_name = self.get_name();
        for (client, score) in self.clients.iter_mut(){
            if(self.current_data.logs.contains_key(client)){
                let (mut score, err_msg) =&self.current_data.logs[client];
                score += score;
                if score > 14{
                    let level:LogType;
                    // let sus_msg:String;
                    if score > 30{
                        if score > 40{
                            if score > 50{
                            level = LogType::Critical;
                            }else{
                                level = LogType::Serious;
                            }
                        }else{
                            level = LogType::Warning;

                        }
                    }else{
                        level = LogType::Info;
                    }
                    let error_msg = format!("Client [{}] - {}", client,  err_msg);
                    results.push(Log::new(level, self_name.clone(), error_msg))
                } 
                
            }
        }
        return results;
    }
    fn get_name(&self) -> String{
        return self.module_name.clone();
    }
    fn build_config_fields(&self) -> Vec<crate::ConfigField> {
        let fields:Vec<ConfigField> = vec![
            ConfigField::new("Access-Log Path".to_owned(),"Path to the Access log for Appache".to_owned(),core_enums::ConfigFieldType::String,vec!["/var/log/apache2/access.log".to_owned()], false),
            ConfigField::new("Error-Log Path".to_owned(),"Path to the Error log for Appache".to_owned(),core_enums::ConfigFieldType::String,vec!["/var/log/apache2/error.log".to_owned()], false)
        ];        

        return fields;
    }
    fn retrieve_config_data(&mut self, data: HashMap<String,Vec<String>>) -> bool{
        for (field, vals) in data.into_iter(){
            if field == "Access-Log Path"{
                if !Path::new(&vals[0]).exists(){
                    let msg = format!("{}",format!("Could not find specified path for Appache Access logs '{}'",&vals[0].italic()).red().bold());
                    println!("{}",msg);
                    return false;
                }else{
                    self.access_path = vals[0].to_string();
                }
            }else if field=="Error-Log Path"{
                if !Path::new(&vals[0]).exists(){
                    let msg = format!("{}",format!("Could not find specified path for Appache error logs '{}'",&vals[0].italic()).red().bold());
                    println!("{}",msg);
                    return false;
                }else{
                    self.error_path = vals[0].to_string();
                }
            }
        }
        return true;
    }
}
// Must implement on your module, defines a default constructor. This is where any code that should run when IDS is FIRST LOADED. 
// You should also initialize an empty current data struct like this
impl Default for HTTPServer {
    fn default() -> Self {
        Self {
            lasterrorlen:0,
            lastaccesslen:0,
            errorinitial:false,
            accessinitial:false,
            access_path:"".to_string(),
            error_path:"".to_string(),
            clients: HashMap::new(),
            module_name: String::from("HTTPServerModule"),
            current_data: CurrentData {
                logs: HashMap::new(),
                veclogs: Vec::new(),
            },
        }
    }
}
