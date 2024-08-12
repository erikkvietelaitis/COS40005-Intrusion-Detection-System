use crate::LaraCore::CoreEnums::*;
use chrono::{DateTime, Local};

pub struct Log {
    message: String,
    module: String,
    time: DateTime<Local>,
    log_type: LogType,
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
