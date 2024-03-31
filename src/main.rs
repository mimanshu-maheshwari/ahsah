use ahsah::{hashes::AhsahHasher, sha512::Sha512};
use std::{
    env::args,
    fs::File,
    io::{BufRead, BufReader},
};

fn main() {
    let mut hasher = Sha512::new();
    let file_path = match args().skip(1).next() {
        Some(val) => val,
        None => String::from("res/test.txt"),
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
