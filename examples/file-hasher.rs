use ahsah::{
    hashes::AhsahHasher,
    sha256::Sha256,
    sha512::Sha512,
    utils::{Args, HasherKind},
};
use clap::Parser;
use std::{
    fs::File,
    io::{BufReader, Read},
};

fn main() {
    let args = Args::parse();
    if let Some(path) = &args.path {
        let file = File::open(path).expect("Unable to open file");
        let mut buf_reader = BufReader::new(file);
        let mut buffer = [0; 1024];
        match &args.kind {
            HasherKind::Sha512 => {
                let mut hasher = Sha512::new();
                while let Ok(n) = buf_reader.read(&mut buffer) {
                    if n == 0 {
                        break;
                    }
                    hasher.digest(&buffer[..n]);
                }
                println!("Hashing {} bytes", hasher.len());
                println!("{}", hasher.finish());
            }
            HasherKind::Sha256 => {
                let mut hasher = Sha256::new();
                while let Ok(n) = buf_reader.read(&mut buffer) {
                    if n == 0 {
                        break;
                    }
                    hasher.digest(&buffer[..n]);
                }
                println!("Hashing {} bytes", hasher.len());
                println!("{}", hasher.finish());
            }
        }
    } else {
        panic!("File path not provided");
    }
}
