use crate::lara_core::core_enums::*;
use chrono::{DateTime, Local};

pub struct Log {
    pub message: String,
    pub module: String,
    pub time: DateTime<Local>,
    pub log_type: LogType,
}
impl Log {
    pub fn new(log_type: LogType, module: String, message: String) -> Self {
        Self {
            log_type: log_type,
            module: module,
            time: Local::now(),
            message: message,
        }
    }
    pub fn build_alert(&self) -> String {
        let mut log: String = String::from("[");
        log.push_str(&self.time.format("%Y-%m-%d %H:%M:%S").to_string());
        log.push_str("]=[");
        log.push_str(&self.module);
        log.push_str("]=[");
        log.push_str(&self.log_type.as_str());
        log.push_str("]:");
        log.push_str(&self.message);
        return log;
    }
}

pub struct ConfigField{
    pub name: String,
    description: String,
    pub field_type: ConfigFieldType,
    pub is_array: bool,
    pub default_values: Vec<String>
}
impl ConfigField {
    pub fn new(name: String, description: String, field_type: ConfigFieldType, default_values: Vec<String>, is_array:bool) -> Self {
        Self {
            name: name,
            description:description,
            field_type: field_type,
            default_values: default_values,
            is_array: is_array
        }
    }
    pub fn build_field(&self)-> String{
        let mut result: String = String::from("\n;");
        result.push_str(&self.description);
        for val in <Vec<std::string::String> as Clone>::clone(&self.default_values).into_iter(){
            result.push_str("\n");
            result.push_str(&self.name);
            if &self.is_array == &true{
                result.push_str("[]");
            }
            result.push_str("=");
            result.push_str(&val);
        }
        return result;
    }
}