use ahsah::hashes::HashBuilder;
use std::io::stdin;

fn main() {
    let mut hasher = HashBuilder::sha256().digester();
    let stdin = stdin(); // We get `Stdin` here.
    for line in stdin.lines() {
        let line = line.expect("Unable to read line from stdin");
        hasher.digest(&line.as_bytes());
    }
    println!("Hashing {} bytes.", hasher.consumed_len());
    println!("{}", hasher.finalize());
}
