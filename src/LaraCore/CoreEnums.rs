pub enum CoreTypes{
    Timed,
    Async
}
pub enum LogType {
    Info,
    Warning,
    Serious,
    Critical,
    IDSFailure
}
impl LogType {
    pub fn as_str(&self) -> &'static str {
        match self {
            LogType::Info => "Info",
            LogType::Warning => "Warning",
            LogType::Serious => "Serious",
            LogType::Critical => "CRITICAL",
            LogType::IDSFailure => "INTERNAL ERROR"
        }
    }
}