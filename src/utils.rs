use std::ops::{BitAnd, BitOr, BitXor, Not, Shl, Shr};

#[cfg(feature = "args")]
use clap::{Parser, ValueEnum};

#[cfg(feature = "args")]
#[derive(Debug, ValueEnum, Clone)]
pub enum HashingAlgo {
    Sha512,
    Sha256,
    MD5,
}

#[cfg(feature = "args")]
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    /// Type of hasher you want to run.
    #[arg(short, long, value_enum)]
    pub algo: HashingAlgo,

    /// File path, if file path is not given will expect stdin
    #[arg(short, long)]
    pub file: Option<String>,

    /// Record time taken by hasher
    #[arg(short, long)]
    pub time: bool,
}

/// Big sigma (upper-case): right_rotate ^ right_rotate ^ right_rotate
pub(crate) fn big_sigma<T>(x: T, (a, b, c): (usize, usize, usize)) -> T
where
    T: Shr<usize, Output = T>
        + Shl<usize, Output = T>
        + BitOr<T, Output = T>
        + BitXor<T, Output = T>
        + Clone
        + Copy,
{
    right_rotate(x, a) ^ right_rotate(x, b) ^ right_rotate(x, c)
}

/// Small sigma (lower-case): right_rotate ^ right_rotate ^ right_shift
pub(crate) fn small_sigma<T>(x: T, (a, b, c): (usize, usize, usize)) -> T
where
    T: Shr<usize, Output = T>
        + Shl<usize, Output = T>
        + BitOr<T, Output = T>
        + BitXor<T, Output = T>
        + Clone
        + Copy,
{
    right_rotate(x, a) ^ right_rotate(x, b) ^ right_shift(x, c)
}

pub(crate) fn left_rotate<T>(num: T, bits: usize) -> T
where
    T: Shr<usize, Output = T> + Shl<usize, Output = T> + BitOr<T, Output = T> + Clone,
{
    let bit_width = std::mem::size_of_val(&num) * 8;
    let bits = bits % bit_width;
    (num.clone() << bits) | (num >> (bit_width - bits))
}

pub(crate) fn right_rotate<T>(num: T, bits: usize) -> T
where
    T: Shr<usize, Output = T> + Shl<usize, Output = T> + BitOr<T, Output = T> + Clone,
{
    let bit_width = std::mem::size_of_val(&num) * 8;
    let bits = bits % bit_width;
    (num.clone() << (bit_width - bits)) | (num >> bits)
}

pub(crate) fn right_shift<T>(num: T, bits: usize) -> T
where
    T: Shr<usize, Output = T>,
{
    let bits = bits % (std::mem::size_of::<T>() * 8);
    num >> bits
}

/// Ch function: works on e, f, g
pub(crate) fn ch<T>(x: T, y: T, z: T) -> T
where
    T: BitAnd<T, Output = T> + BitXor<T, Output = T> + Not<Output = T> + Copy,
{
    (x & y) ^ (!x & z)
}

/// Maj function: works on a, b, c
pub(crate) fn maj<T>(x: T, y: T, z: T) -> T
where
    T: BitAnd<T, Output = T> + BitXor<T, Output = T> + Copy,
{
    (x & y) ^ (x & z) ^ (y & z)
}
