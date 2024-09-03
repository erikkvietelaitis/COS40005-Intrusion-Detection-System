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

