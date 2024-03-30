use std::fs;
use ahsah::{hashes::AhsahHasher, sha256::Sha256};

fn main() {
    let mut hasher = Sha256::new();
    let file_path = "res/poem.txt";
    let contents = fs::read_to_string(file_path)
        .expect("Should have been able to read the file");
    hasher.digest(&contents.as_bytes());
    println!("{}", hasher.finish());
}
