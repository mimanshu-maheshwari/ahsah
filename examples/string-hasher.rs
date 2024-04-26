use ahsah::hashes::HashBuilder;
use std::env::args;

fn main() {
    let message = match args().skip(1).next() {
        Some(name) => name,
        None => panic!("No message provided to encode"),
    };
    let mut hasher = HashBuilder::sha256().digester();
    hasher.digest(&message.as_bytes());
    println!("Hashing {} bytes.", hasher.consumed_len());
    println!("{}", hasher.finalize());
}
