use std::fmt::LowerHex;
use std::ops::{BitOr, Shl, Shr};

/// Message buffer size in bits
const BUFFER_SIZE_BITS: usize = 512;
/// Message buffer size in bytes
const BUFFER_SIZE_U8: usize = BUFFER_SIZE_BITS / 8;
const BUFFER_SIZE_U32: usize = BUFFER_SIZE_BITS / 32;

const MESSAGE_SCHEDULE_SIZE: usize = 64;

/// Hash size in 4bytes
const HASH_SIZE_BITS: usize = 256;
const HASH_SIZE_U32: usize = HASH_SIZE_BITS / 32;

const LENGTH_VALUE_PADDING_SIZE_BITS: usize = 64;

const H: [u32; HASH_SIZE_U32] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const K: [u32; BUFFER_SIZE_U8] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Main hasher function
pub fn hash(msg: &[u8]) -> String {
    let msg_len: usize = msg.len();

    println!("INFO: Recived message of length: {msg_len}");

    // A single u32 in this buffer is a word of size 32 bits
    let mut chunk = [0; BUFFER_SIZE_U32];

    let mut temp_block_buf: Vec<u8> = Vec::from(msg);

    // println!( "INFO: created a temporary buffer of len: {}", temp_block_buf.len());
    // read message data into temporary buffer.

    /* padding message start */
    add_padding(&mut temp_block_buf, msg_len);
    /* padding message end */

    //print_buf(&temp_block_buf)
    let mut hash_value = H.clone();

    for i in (0..temp_block_buf.len()).step_by(BUFFER_SIZE_U8) {
        // copy into active block buffer
        copy_buf_u8_to_u32(&mut temp_block_buf, &mut chunk, i);

        // initialize registers
        // message schedule array
        let mut w = [0; MESSAGE_SCHEDULE_SIZE];

        w[0..16].copy_from_slice(&chunk[..]);
        for i in 16..=63 {
            let sigma_0 = sigma_0(w[i - 15]);
            let sigma_1 = sigma_1(w[i - 2]);
            w[i] = sigma_0
                .wrapping_add(sigma_1)
                .wrapping_add(w[i - 16])
                .wrapping_add(w[i - 7]);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = hash_value.clone();
        compression(
            &w,
            (
                &mut a, &mut b, &mut c, &mut d, &mut e, &mut f, &mut g, &mut h,
            ),
        );
        hash_value[0] = a.wrapping_add(hash_value[0]);
        hash_value[1] = b.wrapping_add(hash_value[1]);
        hash_value[2] = c.wrapping_add(hash_value[2]);
        hash_value[3] = d.wrapping_add(hash_value[3]);
        hash_value[4] = e.wrapping_add(hash_value[4]);
        hash_value[5] = f.wrapping_add(hash_value[5]);
        hash_value[6] = g.wrapping_add(hash_value[6]);
        hash_value[7] = h.wrapping_add(hash_value[7]);
    }

    format!(
        "{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}",
        hash_value[0],
        hash_value[1],
        hash_value[2],
        hash_value[3],
        hash_value[4],
        hash_value[5],
        hash_value[6],
        hash_value[7]
    )
}

/// Ch function will work on e, f, g
fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}
/// Maj function will work on a, b, c
fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}
///Σ0 will work on a
fn sum_0(x: u32) -> u32 {
    right_rotate(x, 2) ^ right_rotate(x, 13) ^ right_rotate(x, 22)
}

///Σ1 will work on e
fn sum_1(x: u32) -> u32 {
    right_rotate(x, 6) ^ right_rotate(x, 11) ^ right_rotate(x, 25)
}

/// σ0 will work on
fn sigma_0(x: u32) -> u32 {
    right_rotate(x, 7) ^ right_rotate(x, 18) ^ right_shift(x, 3)
}

/// σ1 will work on
fn sigma_1(x: u32) -> u32 {
    right_rotate(x, 17) ^ right_rotate(x, 19) ^ right_shift(x, 10)
}

fn compression(
    w: &[u32; MESSAGE_SCHEDULE_SIZE],
    (a, b, c, d, e, f, g, h): (
        &mut u32,
        &mut u32,
        &mut u32,
        &mut u32,
        &mut u32,
        &mut u32,
        &mut u32,
        &mut u32,
    ),
) {
    for i in 0..64 {
        let sum_1 = sum_1(*e);
        let ch = ch(*e, *f, *g);
        let temp_1 = h
            .wrapping_add(sum_1)
            .wrapping_add(ch)
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let sum_0 = sum_0(*a);
        let maj = maj(*a, *b, *c);
        let temp_2 = sum_0.wrapping_add(maj);
        *h = *g;
        *g = *f;
        *f = *e;
        *e = d.wrapping_add(temp_1);
        *d = *c;
        *c = *b;
        *b = *a;
        *a = temp_1.wrapping_add(temp_2);
    }
}

fn right_rotate<T>(num: T, bits: usize) -> T
where
    T: Shr<usize, Output = T> + Shl<usize, Output = T> + BitOr<T, Output = T> + Clone,
{
    let bit_width = std::mem::size_of_val(&num) * 8;
    let bits = bits % bit_width;
    (num.clone() << (bit_width - bits)) | (num.clone() >> (bits))
}

fn right_shift<T>(num: T, bits: usize) -> T
where
    T: Shr<usize, Output = T> + Shl<usize, Output = T> + BitOr<T, Output = T>,
{
    let bits = bits % 32;
    num >> (bits)
}

#[allow(unused)]
fn print_buf<T>(buf: &[T]) -> ()
where
    T: LowerHex,
{
    print!("Buffer:\n[ ");
    for i in 0..buf.len() {
        print!("0x{val:08x} ", val = buf[i]);
    }
    println!("]");
}

fn add_padding(temp_block_buf: &mut Vec<u8>, msg_len: usize) {
    // length of message in bits.
    let l = temp_block_buf.len() * 8;
    // println!("INFO: L: {l} bits or {} bytes", l / 8);

    // add a bit at the end of message
    temp_block_buf.push(0x80);

    // println!("INFO: added one bit or byte 0x80 at end of temporary buffer");
    let k = k_value(l, Some(8)) / 8;

    // add one bit
    // add zero padding
    let mut padding = vec![0; k];
    temp_block_buf.append(&mut padding);
    // println!("INFO: Added {} bits or {k} bytes to the buffer", k * 8);

    // add message length
    copy_len_to_buf(temp_block_buf, msg_len);
}

/// will copy the data of u8 vec into a array of u32.
/// we can assert for u8_block remaining bytes length but it should not fail because we
/// will be padding the vec before copying the data int buffer block.
fn copy_buf_u8_to_u32(u8_block: &[u8], u32_block: &mut [u32; BUFFER_SIZE_U32], start: usize) {
    assert!(
        BUFFER_SIZE_U8 <= u8_block.len() - start,
        "Remaining bits in buffer are {val}, Expected {BUFFER_SIZE_U8} bits",
        val = (u8_block.len() - start)
    );
    for i in 0..BUFFER_SIZE_U32 {
        u32_block[i] = (u8_block[start + (i * 4) + 0] as u32) << 24
            | (u8_block[start + (i * 4) + 1] as u32) << 16
            | (u8_block[start + (i * 4) + 2] as u32) << 8
            | (u8_block[start + (i * 4) + 3]) as u32;
    }
}

/// find the k value for given length
/// (L + 1 + k + 64) mod 512 = 0
fn k_value(l: usize, one_bit: Option<usize>) -> usize {
    let padding_size = LENGTH_VALUE_PADDING_SIZE_BITS;
    let buffer_size = BUFFER_SIZE_BITS;
    match one_bit {
        None => (buffer_size - ((l + padding_size + 1) % buffer_size)) % buffer_size,
        Some(v) => (buffer_size - ((l + padding_size + v) % buffer_size)) % buffer_size,
    }
}

fn copy_len_to_buf(temp_block_buf: &mut Vec<u8>, len: usize) {
    temp_block_buf.push((len >> 56) as u8 & 0xff);
    temp_block_buf.push((len >> 48) as u8 & 0xff);
    temp_block_buf.push((len >> 40) as u8 & 0xff);
    temp_block_buf.push((len >> 32) as u8 & 0xff);
    temp_block_buf.push((len >> 24) as u8 & 0xff);
    temp_block_buf.push((len >> 16) as u8 & 0xff);
    temp_block_buf.push((len >> 8) as u8 & 0xff);
    temp_block_buf.push((len >> 0) as u8 & 0xff);
}
