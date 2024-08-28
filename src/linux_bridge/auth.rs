use std::process::Command;

//Function to view the user who  logged in and out and how long for 
pub fn last() -> String {
    let output = Command::new("last")
        .output()
        .expect("Failed to execute command");
    let last = String::from_utf8_lossy(&output.stdout);
    return last.to_string();
}

//Function to view the last reboot of the system
pub fn last_reboot() -> String {
    let output = Command::new("last")
        .arg("reboot")
        .output()
        .expect("Failed to execute command");
    let last_reboot = String::from_utf8_lossy(&output.stdout);
    return last_reboot.to_string();
}

//Function to view the last shutdown of the system
pub fn last_shutdown() -> String {
    let output = Command::new("last")
        .arg("shutdown")
        .output()
        .expect("Failed to execute command");
    let last_shutdown = String::from_utf8_lossy(&output.stdout);
    return last_shutdown.to_string();
}

//Function to view the last login of the system
pub fn last_login() -> String {
    let output = Command::new("last")
        .arg("-F")
        .output()
        .expect("Failed to execute command");
    let last_login = String::from_utf8_lossy(&output.stdout);
    return last_login.to_string();
}

//Funtion to view the plan text UTMP dump Eg this is a dump of the WTMP binary file
//This file contains the history of all the logins and logouts and restarts of the system, this dump should not be need
//as we are using the previous command calls
pub fn wtmp_dump() -> String {
    let output = Command::new("utmpdump")
        .arg("/var/log/wtmp")
        .output()
        .expect("Failed to execute command");
    let wtmpdump = String::from_utf8_lossy(&output.stdout);
    return wtmpdump.to_string();
}

//Function to get the current user of the system. Eg Erik
pub fn system_user() -> String {
   let output = Command::new("whoami")
        .output()
        .expect("Failed to execute command");
    let user = String::from_utf8_lossy(&output.stdout);
    return user.to_string();
}
//prints the current uptime of the system

pub fn system_uptime() -> String {
    let output = Command::new("uptime")
        .output()
        .expect("Failed to execute command");
    let uptime = String::from_utf8_lossy(&output.stdout);
    return uptime.to_string();
}
//prints all the current users on the system

pub fn all_system_user() -> String {
   let output = Command::new("who")
        .output()
        .expect("Failed to execute command");
    let user = String::from_utf8_lossy(&output.stdout);
    return user.to_string();
}

//prints the last system boot time
pub fn all_system_user_boottime() -> String {
   let output = Command::new("who -b")
        .output()
        .expect("Failed to execute command");
    let user = String::from_utf8_lossy(&output.stdout);
    return user.to_string();
}

//Function to get the BTMP dump file
//NOTE: You will be prompted to enter your password to view the file, this will be like entering 
//sudo utmpdump /var/log/btmp in the terminal and entering your password where it does not show up
pub fn btmp_dump() -> String {
    let output = Command::new("sudo")
        .arg("utmpdump")
        .arg("/var/log/btmp")
        .output()
        .expect("Failed to execute command");
    let btmpdump = String::from_utf8_lossy(&output.stdout);
    return btmpdump.to_string();
}