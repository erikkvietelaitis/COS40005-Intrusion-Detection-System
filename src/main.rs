use crate::LaraCore::CoreEnums::*;
use crate::LaraCore::CoreStruts::*;
pub mod LaraCore;


mod linux_bridge; 
use crate::linux_bridge::linux::system_time;

fn main(){
       println!("Welcome to L.A.R.A.!");
       system_time();
}



