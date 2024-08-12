
use crate::LaraCore::CoreStruts::*;
use std::time::*;

pub trait AnalysisModule{
    fn perform_analysis(&self) -> Vec<Log>;
    fn new() -> Self;
}