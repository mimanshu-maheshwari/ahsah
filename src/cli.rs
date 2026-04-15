#[cfg(feature = "args")]
use std::path::PathBuf;

#[cfg(feature = "args")]
use clap::{Parser, ValueEnum};

#[cfg(feature = "args")]
#[derive(Debug, ValueEnum, Clone, Copy, Eq, PartialEq)]
pub enum HashingAlgo {
    Md5,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

#[cfg(feature = "args")]
#[derive(Parser, Debug)]
#[command(version, about = "Hash files or stdin with AHSAH digest contexts")]
pub struct Args {
    #[arg(short = 'a', long, value_enum)]
    pub algo: HashingAlgo,

    #[arg(short, long)]
    pub file: Option<PathBuf>,

    #[arg(short, long)]
    pub time: bool,
}
