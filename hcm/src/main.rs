use std::io;

fn main() {
    println(hash)
}

fn hashthis() {
    let mut temp_file = HashThisFile::new()?;
    io::copy(&mut input, &mut temp_file)?;
    temp_file.flush()?;
    let temp_path = temp_file.path().to_str()
}
