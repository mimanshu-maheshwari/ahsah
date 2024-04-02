use ahsah::{hashes::AhsahHasher, sha512::Sha512, sha256::Sha256};
use std::{
    fs::File,
    io::{BufReader, Read},
};

use clap::{Parser, ValueEnum};

#[derive(Debug, ValueEnum, Clone)]
enum HasherKind {
    Sha512,
    Sha256,
}

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {

    /// Type of hasher you want to run.
    // #[arg(short, long)]
    #[arg(short, long, value_enum)]
    kind: HasherKind,

    /// Path to file
    #[arg(short, long)]
    path: String,
}

fn main() {
    let args = Args::parse();
    let file = File::open(&args.path).expect("Unable to open file");
    let mut buf_reader = BufReader::new(file);
    let mut buffer = [0; 1024]; 
    match &args.kind {
        HasherKind::Sha512 =>{
            let mut hasher = Sha512::new();
            while let Ok(n) = buf_reader.read(&mut buffer) {
                if n == 0 {
                    break;
                }
                hasher.digest(&buffer[..n]);
            }
            println!("Hashing {} bytes", hasher.len());
            println!("{}", hasher.finish());


        } ,
        HasherKind::Sha256 =>{
            let mut hasher = Sha256::new();
            while let Ok(n) = buf_reader.read(&mut buffer) {
                if n == 0 {
                    break;
                }
                hasher.digest(&buffer[..n]);
            }
            println!("Hashing {} bytes", hasher.len());
            println!("{}", hasher.finish());

        } ,
    }
}
