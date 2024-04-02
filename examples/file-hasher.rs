use ahsah::{hashes::AhsahHasher, sha512::Sha512, sha256::Sha256};
use std::{
    fs::File,
    io::{BufReader, Read},
};

use clap::Parser;

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// type of hasher you want to run. option can be sha512 and sha256
    #[arg(short, long, default_value_t = String::from("sha256"))]
    kind: String,

    /// path to file
    #[arg(short, long)]
    path: String,
}

fn main() {
    let args = Args::parse();
    let file = File::open(&args.path).expect("Unable to open file");
    let mut buf_reader = BufReader::new(file);
    let mut buffer = [0; 1024]; 
    if &args.kind == "sha512" {
        let mut hasher = Sha512::new();
        while let Ok(n) = buf_reader.read(&mut buffer) {
            if n == 0 {
                break;
            }
            hasher.digest(&buffer[..n]);
        }
        println!("Hashing {} bytes", hasher.len());
        println!("{}", hasher.finish());

    } else {
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
