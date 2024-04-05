use ahsah::{hashes::AhsahHasher, sha256::Sha256};
use std::env::args;

fn main() {
    let message = match args().skip(1).next() {
        Some(name) => name,
        None => panic!("No message provided to encode"),
    };
    let mut hasher = Sha256::new();
    hasher.digest(&message.as_bytes());
    println!("Hashing {} bytes.", hasher.consumed_len());
    println!("{}", hasher.finish());
}
