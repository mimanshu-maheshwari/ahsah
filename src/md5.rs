use crate::hashes::{Generic, Hasher, WithReader, WithoutReader};
use crate::utils::k_value;
use crate::utils::left_rotate;
use std::io::Read;
use std::marker::PhantomData;

/// Message buffer size in bits
const BUFFER_SIZE_BITS: usize = 512;
const BUFFER_SIZE_U8: usize = BUFFER_SIZE_BITS / 8;
const BUFFER_SIZE_U32: usize = BUFFER_SIZE_BITS / 32;

const HASH_SIZE_BITS: usize = 128;
const HASH_SIZE_U32: usize = HASH_SIZE_BITS / 32;

const LENGTH_VALUE_PADDING_SIZE_BITS: usize = 64;
const MESSAGE_SCHEDULE_SIZE: usize = 16;

// s specifies the per-round shift amounts
const S: [usize; BUFFER_SIZE_U8] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15,
    21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

// Initialize variables:
const H: [u32; 4] = [
    0x67452301, // A
    0xefcdab89, // B
    0x98badcfe, // C
    0x10325476, // D
];

// Use binary integer part of the sines of integers (Radians) as constants:
// for i from 0 to 63 do
//     K[i] := floor(232 × abs(sin(i + 1)))
// end for
// (Or just use the following precomputed table):
const K: [u32; BUFFER_SIZE_U8] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

#[derive(Debug)]
pub struct MD5 {
    data: Vec<u8>,
    hashes: [u32; HASH_SIZE_U32],
    chunk: [u32; BUFFER_SIZE_U32],
    bytes_len: usize,
}

impl Default for MD5 {
    fn default() -> Self {
        Self {
            data: Vec::new(),
            hashes: H,
            bytes_len: 0,
            chunk: [0; BUFFER_SIZE_U32],
        }
    }
}

impl MD5 {
    /// create a new instance of hasher
    pub(crate) fn new() -> Self {
        Self {
            data: Vec::new(),
            hashes: H,
            bytes_len: 0,
            chunk: [0; BUFFER_SIZE_U32],
        }
    }

    fn add_padding(temp_block_buf: &mut Vec<u8>, len: Option<usize>) {
        // length of message in bits.
        let l = match len {
            None => temp_block_buf.len() * 8,
            Some(val) => val * 8,
        };

        // add a bit at the end of message
        temp_block_buf.push(0x80u8);

        let k = k_value(l, Some(8), LENGTH_VALUE_PADDING_SIZE_BITS, BUFFER_SIZE_BITS) / 8;

        // add one bit
        // add zero padding
        let mut padding = vec![0; k];
        temp_block_buf.append(&mut padding);

        // add message length
        Self::copy_len_to_buf(temp_block_buf, l);
    }

    /// will copy the data of u8 vec into a array of u32.
    /// we can assert for u8_block remaining bytes length but it should not fail because we
    /// will be padding the vec before copying the data int buffer block.
    fn copy_buf_u8_to_u32(u8_block: &[u8], u32_block: &mut [u32; BUFFER_SIZE_U32], start: usize) {
        assert!(
            BUFFER_SIZE_U8 <= u8_block.len() - start,
            "Remaining bytes in buffer are {val}, Expected {BUFFER_SIZE_U8} bytes",
            val = (u8_block.len() - start)
        );
        for i in 0..BUFFER_SIZE_U32 {
            u32_block[i] = (u8_block[start + (i * 4)] as u32) << 24
                | (u8_block[start + (i * 4) + 1] as u32) << 16
                | (u8_block[start + (i * 4) + 2] as u32) << 8
                | (u8_block[start + (i * 4) + 3]) as u32;
        }
    }

    /// copy the length of data to buffer.
    fn copy_len_to_buf(temp_block_buf: &mut Vec<u8>, len: usize) {
        temp_block_buf.push((len >> 56) as u8);
        temp_block_buf.push((len >> 48) as u8);
        temp_block_buf.push((len >> 40) as u8);
        temp_block_buf.push((len >> 32) as u8);
        temp_block_buf.push((len >> 24) as u8);
        temp_block_buf.push((len >> 16) as u8);
        temp_block_buf.push((len >> 8) as u8);
        temp_block_buf.push((len) as u8);
    }

    fn compression(
        w: &[u32; MESSAGE_SCHEDULE_SIZE],
        (a, b, c, d): (&mut u32, &mut u32, &mut u32, &mut u32),
    ) {
        for i in 0..64 {
            let mut f: u32;
            let g: u32;
            if i <= 15 {
                f = (*b & *c) | (!*b & *d);
                g = i % 16;
            } else if 16 <= i && i <= 31 {
                f = (*d & *b) | (!*d & *c);
                g = (5 * i + 1) % 16;
            } else if 32 <= i && i <= 47 {
                f = *b ^ *c ^ *d;
                g = (3 * i + 5) % 16;
            } else {
                f = *c ^ (*b | !*d);
                g = (7 * i) % 16;
            }
            f = f + *a + K[i as usize] + w[g as usize]; // m[g] must be a 32-bit block
            *a = *d;
            *d = *c;
            *c = *b;
            *b = *b + left_rotate(f, S[i as usize]);
        }
    }
    fn hash_algo(&mut self) {
        let [mut a, mut b, mut c, mut d] = &self.hashes.clone();
        MD5::compression(&self.chunk, (&mut a, &mut b, &mut c, &mut d));
        self.hashes[0] = a.wrapping_add(self.hashes[0]);
        self.hashes[1] = b.wrapping_add(self.hashes[1]);
        self.hashes[2] = c.wrapping_add(self.hashes[2]);
        self.hashes[3] = d.wrapping_add(self.hashes[3]);
    }

    fn get_hash_string(&self) -> String {
        format!(
            "{:08x}{:08x}{:08x}{:08x}",
            self.hashes[0], self.hashes[1], self.hashes[2], self.hashes[3],
        )
    }
}

impl Hasher<MD5, Generic> {
    pub fn reader(self) -> Hasher<MD5, WithReader> {
        let hasher: Hasher<MD5, WithReader> = Hasher::<MD5, WithReader> {
            algo: self.algo,
            phantom: PhantomData,
        };
        hasher
    }
    pub fn digester(self) -> Hasher<MD5, WithoutReader> {
        let hasher: Hasher<MD5, WithoutReader> = Hasher::<MD5, WithoutReader> {
            algo: self.algo,
            phantom: PhantomData,
        };
        hasher
    }
}

impl Hasher<MD5, WithReader> {
    /// the length of data that is hashed in bytes
    pub fn consumed_len(&self) -> usize {
        self.algo.bytes_len
    }

    /// hashing algorithm
    pub fn read(&mut self, handle: &mut dyn Read) -> String {
        let mut buffer = [0; BUFFER_SIZE_U8];
        while let Ok(n) = handle.read(&mut buffer) {
            self.algo.bytes_len += n;
            if n == 0 {
                break;
            } else if n == BUFFER_SIZE_U8 {
                MD5::copy_buf_u8_to_u32(&buffer, &mut self.algo.chunk, 0);
                self.algo.hash_algo();
            } else {
                let mut data = Vec::new();
                for d in &buffer[..n] {
                    data.push(*d);
                }
                MD5::add_padding(&mut data, Some(self.algo.bytes_len));
                for i in (0..data.len()).step_by(BUFFER_SIZE_U8) {
                    MD5::copy_buf_u8_to_u32(&data, &mut self.algo.chunk, i);
                    self.algo.hash_algo();
                }
            }
        }
        self.algo.get_hash_string()
    }
}

impl Hasher<MD5, WithoutReader> {
    pub fn consumed_len(&self) -> usize {
        self.algo.data.len()
    }

    pub fn digest(&mut self, data: &[u8]) {
        for byte in data {
            self.algo.data.push(*byte);
        }
    }

    /// Main hasher function
    pub fn finalize(&mut self) -> String {
        MD5::add_padding(&mut self.algo.data, None);

        for i in (0..self.algo.data.len()).step_by(BUFFER_SIZE_U8) {
            MD5::copy_buf_u8_to_u32(&self.algo.data, &mut self.algo.chunk, i);
            self.algo.hash_algo();
        }
        self.algo.get_hash_string()
    }
}
