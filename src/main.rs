use sha256::hash;
use std::env::args;

fn main() {
    let args = args();
    let message: String = match args.skip(1).next() {
        Some(val) => val,
        None => String::from("abc"),
    };
    if let Some(val) = hash(message.as_bytes()){
        println!("{val}");
    }
}
