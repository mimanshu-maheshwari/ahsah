use std::ops::{BitAnd, BitOr, BitXor, Not, Shl, Shr};

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
