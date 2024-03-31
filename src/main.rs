use ahsah::{hashes::AhsahHasher, sha256::Sha256};
use std::{
    fs::File,
    io::{BufRead, BufReader},
    env::args,
};

fn main() {
    let mut hasher = Sha256::new();
    let file_path = match args().skip(1).next() {
        Some(val) => val,
        None => String::from("res/poem.txt"),
    };
    let file = File::open(&file_path).expect("Unable to open file");
    let buf_reader = BufReader::new(file);
    for line in buf_reader.lines() {
        let line = line.expect("Unable to read line");
        hasher.digest(&line.as_bytes());
    }
    println!("Hashing {} bytes", hasher.len());
    println!("{}", hasher.finish());
}
