use ahsah::utils::{Args, HashingAlgo::*};
use ahsah::hashes::HashBuilder;
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

    let hash = match args.algo {
        Sha512 => HashBuilder::sha512().reader().read(&mut handle),
        Sha256 => HashBuilder::sha256().reader().read(&mut handle),
    };

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
