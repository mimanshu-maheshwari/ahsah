use ahsah::{update_reader, Args, Digest, HashingAlgo, Md5, Sha224, Sha256, Sha384, Sha512};
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
        HashingAlgo::Md5 => digest_reader::<Md5>(&mut handle),
        HashingAlgo::Sha224 => digest_reader::<Sha224>(&mut handle),
        HashingAlgo::Sha256 => digest_reader::<Sha256>(&mut handle),
        HashingAlgo::Sha384 => digest_reader::<Sha384>(&mut handle),
        HashingAlgo::Sha512 => digest_reader::<Sha512>(&mut handle),
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

fn digest_reader<D: Digest + Default>(handle: &mut dyn Read) -> String {
    let mut digest = D::default();
    update_reader(&mut digest, handle).expect("Unable to hash reader input");
    digest.finalize_hex()
}
