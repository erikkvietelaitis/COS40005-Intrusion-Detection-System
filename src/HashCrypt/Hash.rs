use std::io::{self, Read, Write};
use std::process::Command;
use tempfile::NamedTempFile;
use std::io::{self, Cursor};

 pub fn compute_hash<R: Read>(mut input: R) -> io::Result<String> {
    
    let mut temp_file = NamedTempFile::new()?;
    io::copy(&mut input, &mut temp_file)?;
    temp_file.flush()?;
    let temp_file_path = temp_file.path().to_str().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Failed to convert temp file path to string"))?;
    let output = Command::new("hashthis")
        .arg("-source")
        .arg(temp_file_path)
        .output()?;
    if !output.status.success() {
        return Err(io::Error::new(io::ErrorKind::Other, "Failed to compute hash"));
    }
    let hash = String::from_utf8(output.stdout).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    Ok(hash.trim().to_string())
}

#[test]
fn test_hash() {
    let data = b"test";
    let cursor = Cursor::new(data);
    let result = compute_hash(cursor).expect("It broken...");
    assert!(!result.is_empty(), "Why empty?");

}