use ahsah::{hashes::AhsahHasher, sha256::Sha256};
use std::env::args;

fn main() {
    let args = args();
    let message: String = match args.skip(1).next() {
        Some(val) => val,
        None => String::from("abc"),
    };
    let mut hasher = Sha256::new();
    hasher.digest(message.as_bytes());
    println!("{}", hasher.finish());
}
