use std::io::{stdin, Read};
use ahsah::{hashes::AhsahHasher, sha256::Sha256};

fn main() {
    let mut stdin = stdin().lock();
    let mut contents = Vec::new();
    stdin.read(&mut contents).expect("unable to read data from stdin");
    drop(stdin);
    let mut hasher = Sha256::new();
    hasher.digest(&contents);
    println!("{}", hasher.finish());
}
