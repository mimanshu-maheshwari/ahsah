use ahsah::{
    hashes::AhsahHasher,
    sha256::Sha256,
    sha512::Sha512,
    utils::{Args, HasherKind},
};
use clap::Parser;
use std::{
    fs::File,
    io::{stdin, BufReader, Read},
    path::Path,
};

fn main() {
    let args = Args::parse();
    let mut handle: Box<dyn Read> = match args.path {
        Some(path) => {
            let path = Path::new(&path);
            Box::new(BufReader::new(File::open(path).unwrap()))
        }
        None => Box::new(stdin().lock()),
    };
    match args.kind {
        HasherKind::Sha512 => {
            let mut hasher = Sha512::new();
            println!("{}", hasher.hash_bufferd(&mut handle));
        }
        HasherKind::Sha256 => {
            let mut hasher = Sha256::new();
            println!("{}", hasher.hash_bufferd(&mut handle));
        }
    }
}
