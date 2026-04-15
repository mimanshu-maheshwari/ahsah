use ahsah::{update_reader, Args, Digest, HashingAlgo, Md5, Sha224, Sha256, Sha384, Sha512};

use clap::Parser;
use std::fs::File;

fn main() {
    let args = Args::parse();
    if let Some(path) = &args.file {
        let mut handle = Box::new(File::open(path).expect("Unable to open file"));
        let hash = match &args.algo {
            HashingAlgo::Md5 => digest_file::<Md5>(&mut handle),
            HashingAlgo::Sha224 => digest_file::<Sha224>(&mut handle),
            HashingAlgo::Sha256 => digest_file::<Sha256>(&mut handle),
            HashingAlgo::Sha384 => digest_file::<Sha384>(&mut handle),
            HashingAlgo::Sha512 => digest_file::<Sha512>(&mut handle),
        };
        println!("{}", hash);
    } else {
        panic!("File path not provided");
    }
}

fn digest_file<D: Digest + Default>(handle: &mut File) -> String {
    let mut digest = D::default();
    update_reader(&mut digest, handle).expect("Unable to hash file");
    digest.finalize_hex()
}
