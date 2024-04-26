use ahsah::utils::{Args, HashingAlgo::*};
use ahsah::{hashes::BufferedHasher, sha256::Sha256, sha512::Sha512};
use clap::Parser;
use std::{
    fs::File,
    io::{stdin, BufReader, Read},
    path::Path,
    time::Instant,
};

fn main() {
    let args = Args::parse();
    let now = Instant::now();

    let mut handle: Box<dyn Read> = match args.file {
        Some(path) => {
            let path = Path::new(&path);
            Box::new(BufReader::new(File::open(path).unwrap()))
        }
        None => Box::new(stdin().lock()),
    };

    let mut hasher: Box<dyn BufferedHasher> = match args.algo {
        Sha512 => Box::new(Sha512::new()),
        Sha256 => Box::new(Sha256::new()),
    };

    let elapsed = now.elapsed();
    if args.time {
        println!(
            "Setup took ({} ns | {} ms | {} s)",
            elapsed.as_nanos(),
            (elapsed.as_nanos() as f64 / 10e5),
            (elapsed.as_nanos() as f64 / 10e8),
        );
    }

    let now = Instant::now();
    let hash = hasher.hash_bufferd(&mut handle);
    let elapsed = now.elapsed();
    if args.time {
        println!(
            "{:?} took ({} ns | {} ms | {} s)",
            &args.algo,
            elapsed.as_nanos(),
            (elapsed.as_nanos() as f64 / 10e5),
            (elapsed.as_nanos() as f64 / 10e8),
        );
    }
    println!("{}", hash);
}
