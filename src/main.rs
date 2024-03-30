use std::{fs::File, io::Read};

use ahsah::{hashes::AhsahHasher, sha256::Sha256};

fn main() {
    let mut file = match File::open("res/test.txt") {
        Ok(file) => file, 
        Err(err) => panic!("Unable to read file, {}", err),
    };
    let mut hasher = Sha256::new();
    let mut buf = Vec::new();
    file.read(&mut buf).unwrap();
    hasher.digest(&buf);
    println!("{}", hasher.finish());
}
