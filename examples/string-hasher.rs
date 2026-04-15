use ahsah::{Digest, Sha256};
use std::env::args;

fn main() {
    let message = match args().nth(1) {
        Some(name) => name,
        None => panic!("No message provided to encode"),
    };
    let mut hasher = Sha256::new();
    hasher.update(message.as_bytes());
    println!("Hashing {} bytes.", hasher.input_size());
    println!("{}", hasher.finalize_hex());
}
