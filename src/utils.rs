use std::fmt::LowerHex;
use std::ops::{BitAnd, BitOr, BitXor, Not, Shl, Shr};

use clap::{Parser, ValueEnum};

#[derive(Debug, ValueEnum, Clone)]
pub enum HasherKind {
    Sha512,
    Sha256,
}

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {

    /// Type of hasher you want to run.
    // #[arg(short, long)]
    #[arg(short, long, value_enum)]
    pub kind: HasherKind,

    /// Path to file
    #[arg(short, long)]
    pub path: String,
}

#[allow(unused)]
pub(crate) fn print_buf<T>(buf: &[T]) -> ()
where
    T: LowerHex,
{
    print!("\n[ ");
    for i in 0..buf.len() {
        print!("{:x} ", buf[i]);
    }
    println!("]");
}

///Σ0 will work on a
pub(crate) fn sum_0<T>(x: T, (a, b, c): (usize, usize, usize)) -> T
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

///Σ1 will work on e
pub(crate) fn sum_1<T>(x: T, (a, b, c): (usize, usize, usize)) -> T
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

/// σ0 will work on
pub(crate) fn sigma_0<T>(x: T, (a, b, c): (usize, usize, usize)) -> T
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

/// σ1 will work on
pub(crate) fn sigma_1<T>(x: T, (a, b, c): (usize, usize, usize)) -> T
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

pub(crate) fn right_rotate<T>(num: T, bits: usize) -> T
where
    T: Shr<usize, Output = T> + Shl<usize, Output = T> + BitOr<T, Output = T> + Clone,
{
    let bit_width = std::mem::size_of_val(&num) * 8;
    let bits = bits % bit_width;
    (num.clone() << (bit_width - bits)) | (num.clone() >> (bits))
}

pub(crate) fn right_shift<T>(num: T, bits: usize) -> T
where
    T: Shr<usize, Output = T> + Shl<usize, Output = T> + BitOr<T, Output = T>,
{
    let bits = bits % 32;
    num >> (bits)
}

/// Ch function will work on e, f, g
pub(crate) fn ch<T>(x: T, y: T, z: T) -> T
where
    T: BitAnd<T, Output = T> + BitXor<T, Output = T> + Not<Output = T> + Copy,
{
    (x & y) ^ (!x & z)
}

/// Maj function will work on a, b, c
pub(crate) fn maj<T>(x: T, y: T, z: T) -> T
where
    T: BitAnd<T, Output = T> + BitXor<T, Output = T> + Copy,
{
    (x & y) ^ (x & z) ^ (y & z)
}
