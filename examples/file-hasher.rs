use ahsah::{
    hashes::HashBuilder,
    utils::{Args, HashingAlgo::*},
};

use clap::Parser;
use std::fs::File;

fn main() {
    let args = Args::parse();
    if let Some(path) = &args.file {
        let mut handle = Box::new(File::open(path).expect("Unable to open file"));
        let hash = match &args.algo {
            Sha512 => HashBuilder::sha512().reader().read(&mut handle),
            Sha256 => HashBuilder::sha256().reader().read(&mut handle),
        };
        println!("{}", hash);
    } else {
        panic!("File path not provided");
    }
}
