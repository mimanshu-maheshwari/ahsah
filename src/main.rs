use ahsah::{
    hashes::AhsahBufferedHasher,
    sha256::Sha256,
    sha512::Sha512,
    utils::{Args, HashingAlgo::*},
};
use clap::Parser;
use std::{
    fs::File,
    io::{stdin, BufReader, Read},
    path::Path,
};

fn main() {
    let args = Args::parse();

    let mut handle: Box<dyn Read> = match args.file {
        Some(path) => {
            let path = Path::new(&path);
            Box::new(BufReader::new(File::open(path).unwrap()))
        }
        None => Box::new(stdin().lock()),
    };

    let mut hasher: Box<dyn AhsahBufferedHasher> = match args.algo {
        Sha512 => Box::new(Sha512::new()),
        Sha256 => Box::new(Sha256::new()),
    };

    println!("{}", hasher.hash_bufferd(&mut handle));
}
