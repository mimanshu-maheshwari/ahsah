use ahsah::{Digest, Sha256};
use std::io;

fn main() {
    let mut hasher = Sha256::new();
    let stdin = io::stdin();
    for line in stdin.lines() {
        let line = line.expect("Unable to read line from stdin");
        hasher.update(line.as_bytes());
    }
    println!("Hashing {} bytes.", hasher.input_size());
    println!("{}", hasher.finalize_hex());
}
