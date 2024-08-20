use std::fs::File;
use std::io::{self, BufRead, BufReader};


//Basic:: Hard Coded file reading 
pub fn file_read() -> io::Result<()>{
let filepath = "/home/erik/Documents/test.txt";  // Hard coded file path
let file = File::open(filepath)?;
let reader = BufReader::new(file);
    for line in reader.lines(){
        let line = line?;
        println!("{}", line)
    }
    Ok(())
}