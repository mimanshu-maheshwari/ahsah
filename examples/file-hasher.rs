use ahsah::{hashes::AhsahHasher, sha256::Sha256};
use std::env::args;
use std::fs;

fn main() {
    let file_path = match args().skip(1).next() {
        Some(name) => name,
        None => panic!("No file name provided"),
    };
    let mut hasher = Sha256::new();
    let contents = fs::read_to_string(file_path).expect("Should have been able to read the file");
    hasher.digest(&contents.as_bytes());
    println!("Hashing {} bytes.", hasher.len());
    println!("{}", hasher.finish());
}
