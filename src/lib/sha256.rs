use std::fmt::LowerHex;
use std::ops::{Shr, Shl, BitOr};

/// Message buffer size in bits
const BUFFER_SIZE_BITS: usize = 512;
/// Message buffer size in bytes
const BUFFER_SIZE_U8: usize = BUFFER_SIZE_BITS / 8;
const BUFFER_SIZE_U32: usize = BUFFER_SIZE_BITS / 32;

/// Hash size in 4bytes
#[allow(unused)]
const HASH_SIZE_BITS: usize = 256;
#[allow(unused)]
const HASH_SIZE_U32: usize = HASH_SIZE_BITS / 32;

const LENGTH_VALUE_PADDING_SIZE_BITS: usize = 64;
#[allow(unused)]
const BUFFER_SIZE_WITHOUT_LENGTH_BITS: usize = BUFFER_SIZE_BITS - LENGTH_VALUE_PADDING_SIZE_BITS;

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
pub fn hash(msg: &[u8]) -> Option<()> {
    let msg_len: usize = msg.len();
    if msg_len == 0 {
        return None;
    }
    println!("INFO: Recived message of length: {msg_len}");

    // A single u32 in this buffer is a word of size 32 bits
    let mut chunk: [u32; BUFFER_SIZE_U32] = [0; BUFFER_SIZE_U32];

    let mut temp_block_buf: Vec<u8> = Vec::new();
    for i in msg {
        temp_block_buf.push(*i);
    }

    println!(
        "INFO: created a temporary buffer of len: {}",
        temp_block_buf.len()
    );
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
        let a = hash_value[0];
        let b = hash_value[1];
        let c = hash_value[2];
        let d = hash_value[3];
        let e = hash_value[4];
        let f = hash_value[5];
        let g = hash_value[6];
        let h = hash_value[7];
        // print_buf(&chunk);
        for i in 0..BUFFER_SIZE_U32 {}
    }

    Some(())
}

fn _ch(_e: u32, _f: u32, _g: u32) {}
fn _maj(_a: u32, _b: u32, _c: u32) {}
fn _sum_0(_a: u32) {}
fn _sum_1(_e: u32) {}
fn _w_j() {}
fn _compression() {}

fn _right_rotate<T>(num: T, bits: usize) -> T 
where T: Shr<usize, Output = T> + Shl<usize, Output = T> + BitOr<T, Output = T> + Clone
{
    let bit_width = std::mem::size_of_val(&num) * 8;
    let bits = bits % bit_width;
    (num.clone() << (bit_width - bits)) | (num.clone() >> (bits))
}

fn _right_shift<T>(num: T, bits: usize) -> T 
where T: Shr<usize, Output = T> + Shl<usize, Output = T> + BitOr<T, Output = T>
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
    println!("INFO: L: {l} bits or {} bytes", l / 8);

    // add a bit at the end of message
    temp_block_buf.push(0x80);

    println!("INFO: added one bit or byte 0x80 at end of temporary buffer");
    let k = k_value(l, Some(8)) / 8;

    // add one bit
    // add zero padding
    let mut padding = vec![0; k];
    temp_block_buf.append(&mut padding);
    println!("INFO: Added {} bits or {k} bytes to the buffer", k * 8);

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
