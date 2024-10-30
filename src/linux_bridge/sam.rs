use std::process::Command;
use std::str;
//Function call to check the read speed of a disk using the dd command, and return the read speed as a string.
//1024+0 records in
//1024+0 records out
//1073741824 bytes (1.1 GB, 1.0 GiB) copied, 0.355575 s, 3.0 GB/s
//Where 1073741824 bytes is the total bytes read, 0.355575 s is the time taken to write the bytes, and 3.0 GB/s is the read speed.
//Function call to check  the write speed of a disk using the dd command, and return the write speed as a string.
pub fn disk_write_speed() -> String {
    let output = Command::new("dd")
        .arg("if=/dev/zero")
        .arg("of=/tmp/test")
        .arg("bs=1M")
        .arg("count=1024")
        .output()
        .expect("Failed to execute command");
    let last = str::from_utf8(&output.stderr).unwrap();
    return last.to_string();
}

//1024+0 records in
//1024+0 records out
//1073741824 bytes (1.1 GB, 1.0 GiB) copied, 0.118897 s, 9.0 GB/s
//This function is called after the disk read speed function is called, as it requires the test file to be present.
pub fn disk_read_speed() -> String {
    let output = Command::new("dd")
        .arg("if=/tmp/test")
        .arg("of=/dev/null")
        .arg("bs=1M")
        .arg("count=1024")
        .output()
        .expect("Failed to execute command");
    let last = str::from_utf8(&output.stderr).unwrap();
    return last.to_string();
}

//This function is called after the disk read speed function is called, as it requires the test file to be present, and removes the test file.
//Function to remove the test file created by the disk write speed function.
pub fn remove_read_write_file() {
    let output = Command::new("rm")
        .arg("/tmp/test")
        .output()
        .expect("Failed to execute command");
    let last = str::from_utf8(&output.stderr).unwrap();
    println!("{}", last);
}

//Function to check the disk usage // Filesystem      Size  Used Avail Use% Mounted on
//To understand the output of the df command, the following is an example of the output:
// Filesystem      Size  Used Avail Use% Mounted on
// tmpfs           2.4G  1.8M  2.4G   1% /run
// /dev/nvme0n1p5  1.8T   24G  1.7T   2% /
// tmpfs            12G   34M   12G   1% /dev/shm
// tmpfs           5.0M  4.0K  5.0M   1% /run/lock
// efivarfs        128K   58K   66K  47% /sys/firmware/efi/efivars
// tmpfs            12G  4.0M   12G   1% /tmp
// /dev/nvme0n1p1   96M   33M   64M  35% /boot/efi
// tmpfs           2.4G   22M  2.4G   1% /run/user/1000
//The first column is the filesystem, the second column is the size of the filesystem, the third column is the amount of space used,
// the fourth column is the amount of space available, the fifth column is the percentage of space used, and the sixth column is the mount point.
pub fn disk_usage() -> String {
    let output = Command::new("df")
        .arg("-h")
        .output()
        .expect("Failed to execute command");
    let last = str::from_utf8(&output.stdout).unwrap();
    return last.to_string();
}

//Fucntion to check for packet loss using the ping command, and return the packet loss as a string.
//Displays statistics for all network interfaces.
pub fn network_packet_dropped_errors() -> String {
    let output = Command::new("ip")
        .arg("-s")
        .arg("link")
        .output()
        .expect("Failed to execute command");
    let last = str::from_utf8(&output.stdout).unwrap();
    return last.to_string();
}

//Function to pull all the CPU information from the /proc/cpuinfo file, and return the CPU information as a string.
pub fn cpu_info() -> String {
    let output = Command::new("cat")
        .arg("/proc/cpuinfo")
        .output()
        .expect("Failed to execute command");
    let last = str::from_utf8(&output.stdout).unwrap();
    return last.to_string();
}
//Function to pull the memory usage
pub fn memory_usage() -> String {
    let output = Command::new("free")
        .output()
        .expect("Failed to execute command");
    let last = str::from_utf8(&output.stdout).unwrap();
    return last.to_string();
}

use std::process::{Stdio};

//Function to pull the CPU usage  from the top command, store the result in a buffer and return the CPU usage as a string.
  // Run the `top` command and capture its output
    //Running this commnad will print a static output of the top command at the time of execution
    //The output will be in the following format:
//         PID USER      PR  NI    VIRT    RES    SHR S
//   21645 erik      20   0 1138.2g 353900 102828 S
//   21721 erik      20   0 1140.2g 693148  79892 S
//     950 erik      -2   0 2639104 342420 243220 R
//   21624 erik      20   0   32.7g 146748 103584 S
//Where the first column is the PID, the second column is the user, the third column is the priority,
// the fourth column is the nice value, the fifth column is the virtual memory, the sixth column is the resident memory, 
//the seventh column is the shared memory, and the eighth column is the status.

//Where PID is the process ID,
// USER is the user who started the process, 
//PR is the priority of the process, 
//NI is the nice value of the process which is used to set the priority of the process,
// VIRT is the virtual memory used by the process which is the total memory used by the process,
// RES is the resident memory used by the process which is the physical memory used by the process,
// SHR is the shared memory used by the process which is the memory shared by the process,
// S is the status of the process which can be S (sleeping), R (running), D (uninterruptible sleep), Z (zombie), or T (stopped).
pub fn cpu_usage() -> String {
    let output = Command::new("top")
        .arg("-b")   // Run in batch mode, this is necessary to prevent the program from hanging this allows for a capture of the output at the time of execution
        .arg("-n")   
        .arg("1")    
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to start `top` command");
    let output = output
        .wait_with_output() // Wait for the command to finish and capture its output
        .expect("Failed to read `top` output");
    String::from_utf8_lossy(&output.stdout).to_string()
}


