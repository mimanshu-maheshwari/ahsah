use ahsah::{hashes::AhsahHasher, sha512::Sha512};
use std::{
    env::args,
    fs::File,
    io::{BufReader, Read},
};

fn main() {
    let mut hasher = Sha512::new();
    let file_path = match args().skip(1).next() {
        Some(val) => val,
        None => String::from("res/test.txt"),
    };
    let file = File::open(&file_path).expect("Unable to open file");
    let mut buf_reader = BufReader::new(file);
    let mut buffer = [0; 1024]; 
    while let Ok(n) = buf_reader.read(&mut buffer) {
        if n == 0 {
            break;
        }
        hasher.digest(&buffer[..n]);
    }
    println!("Hashing {} bytes", hasher.len());
    println!("{}", hasher.finish());
}
