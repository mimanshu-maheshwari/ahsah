use ahsah::{
    hashes::BufferedHasher,
    sha256::Sha256,
    sha512::Sha512,
    utils::{Args, HashingAlgo::*},
};
use clap::Parser;
use std::fs::File;

fn main() {
    let args = Args::parse();
    if let Some(path) = &args.file {
        let mut handle = Box::new(File::open(path).expect("Unable to open file"));
        let mut hasher: Box<dyn BufferedHasher> = match &args.algo {
            Sha512 => Box::new(Sha512::new()),
            Sha256 => Box::new(Sha256::new()),
        };
        println!("{}", hasher.hash_bufferd(&mut handle));
    } else {
        panic!("File path not provided");
    }
}
