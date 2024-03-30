use std::io::stdin;
use ahsah::{hashes::AhsahHasher, sha256::Sha256};

fn main() {
    let mut hasher = Sha256::new();
    let stdin = stdin(); // We get `Stdin` here.
    for line in stdin.lines(){
        let line = line.expect("Unable to read line from stdin");
        hasher.digest(&line.as_bytes());
    }
    println!("{}", hasher.finish());
}
