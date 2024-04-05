use ahsah::{
    hashes::{AhsahHasher},
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

    let _handle: Box<dyn Read> = match args.path {
        Some(path) => {
            let path = Path::new(&path);
            Box::new(BufReader::new(File::open(path).unwrap()))
        }
        None => Box::new(stdin().lock()),
    };

    let mut hasher: Box<dyn AhsahHasher> = match args.kind {
        HasherKind::Sha512 => Box::new(Sha512::new()),
        HasherKind::Sha256 => Box::new(Sha256::new()),
    };

    // println!("{}", hasher.hash_bufferd(&mut handle));
    println!("{}", hasher.finish());
    
}
