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

///Σ0 will work on a
pub(crate) fn sum_0<T>(x: T) -> T
where
    T: Shr<usize, Output = T>
        + Shl<usize, Output = T>
        + BitOr<T, Output = T>
        + BitXor<T, Output = T>
        + Clone
        + Copy,
{
    right_rotate(x, 2) ^ right_rotate(x, 13) ^ right_rotate(x, 22)
}

///Σ1 will work on e
pub(crate) fn sum_1<T>(x: T) -> T
where
    T: Shr<usize, Output = T>
        + Shl<usize, Output = T>
        + BitOr<T, Output = T>
        + BitXor<T, Output = T>
        + Clone
        + Copy,
{
    right_rotate(x, 6) ^ right_rotate(x, 11) ^ right_rotate(x, 25)
}

/// σ0 will work on
pub(crate) fn sigma_0<T>(x: T) -> T
where
    T: Shr<usize, Output = T>
        + Shl<usize, Output = T>
        + BitOr<T, Output = T>
        + BitXor<T, Output = T>
        + Clone
        + Copy,
{
    right_rotate(x, 7) ^ right_rotate(x, 18) ^ right_shift(x, 3)
}

/// σ1 will work on
pub(crate) fn sigma_1<T>(x: T) -> T
where
    T: Shr<usize, Output = T>
        + Shl<usize, Output = T>
        + BitOr<T, Output = T>
        + BitXor<T, Output = T>
        + Clone
        + Copy,
{
    right_rotate(x, 17) ^ right_rotate(x, 19) ^ right_shift(x, 10)
}
