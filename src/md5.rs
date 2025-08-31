use crate::hashes::{Generic, Hasher, WithReader, WithoutReader};
use crate::utils::k_value;
use crate::utils::left_rotate;
use std::fmt::Write;
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
    // 0x01234567,
    // 0x89abcdef,
    // 0xfedcba98,
    // 0x76543210,
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
// const K: [u32; BUFFER_SIZE_U8] = [
//     0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
//     0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
//     0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
//     0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
//     0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
//     0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
//     0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
//     0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
// ];

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
        // println!("Length: {l}");
        // for i in temp_block_buf {
        //     print!("{:02x} ", i);
        // }
        // println!("");
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
        for (dst, chunk) in u32_block
            .iter_mut()
            .zip(u8_block[start..start + BUFFER_SIZE_U8].chunks_exact(4))
        {
            *dst = u32::from_le_bytes(chunk.try_into().unwrap());
        }
        // for i in 0..BUFFER_SIZE_U32 {
        //     u32_block[i] = u32::from_le_bytes([
        //         u8_block[start + (i * 4)],
        //         u8_block[start + (i * 4) + 1],
        //         u8_block[start + (i * 4) + 2],
        //         u8_block[start + (i * 4) + 3],
        //     ]);
        // }
    }

    /// copy the length of data to buffer.
    fn copy_len_to_buf(temp_block_buf: &mut Vec<u8>, len: usize) {
        let len = len as u64;
        temp_block_buf.extend_from_slice(&len.to_le_bytes());
    }

    fn compression(
        w: &[u32; MESSAGE_SCHEDULE_SIZE],
        a: &mut u32,
        b: &mut u32,
        c: &mut u32,
        d: &mut u32,
    ) {
        /* Round 1 */
        Self::ff(a, b, c, d, w[0], S[0], 0xd76aa478); /* 1 */
        Self::ff(d, a, b, c, w[1], S[1], 0xe8c7b756); /* 2 */
        Self::ff(c, d, a, b, w[2], S[2], 0x242070db); /* 3 */
        Self::ff(b, c, d, a, w[3], S[3], 0xc1bdceee); /* 4 */
        Self::ff(a, b, c, d, w[4], S[4], 0xf57c0faf); /* 5 */
        Self::ff(d, a, b, c, w[5], S[5], 0x4787c62a); /* 6 */
        Self::ff(c, d, a, b, w[6], S[6], 0xa8304613); /* 7 */
        Self::ff(b, c, d, a, w[7], S[7], 0xfd469501); /* 8 */
        Self::ff(a, b, c, d, w[8], S[8], 0x698098d8); /* 9 */
        Self::ff(d, a, b, c, w[9], S[9], 0x8b44f7af); /* 10 */
        Self::ff(c, d, a, b, w[10], S[10], 0xffff5bb1); /* 11 */
        Self::ff(b, c, d, a, w[11], S[11], 0x895cd7be); /* 12 */
        Self::ff(a, b, c, d, w[12], S[12], 0x6b901122); /* 13 */
        Self::ff(d, a, b, c, w[13], S[13], 0xfd987193); /* 14 */
        Self::ff(c, d, a, b, w[14], S[14], 0xa679438e); /* 15 */
        Self::ff(b, c, d, a, w[15], S[15], 0x49b40821); /* 16 */

        /* Round 2 */
        Self::gg(a, b, c, d, w[1], S[16], 0xf61e2562); /* 17 */
        Self::gg(d, a, b, c, w[6], S[17], 0xc040b340); /* 18 */
        Self::gg(c, d, a, b, w[11], S[18], 0x265e5a51); /* 19 */
        Self::gg(b, c, d, a, w[0], S[19], 0xe9b6c7aa); /* 20 */
        Self::gg(a, b, c, d, w[5], S[20], 0xd62f105d); /* 21 */
        Self::gg(d, a, b, c, w[10], S[21], 0x2441453); /* 22 */
        Self::gg(c, d, a, b, w[15], S[22], 0xd8a1e681); /* 23 */
        Self::gg(b, c, d, a, w[4], S[23], 0xe7d3fbc8); /* 24 */
        Self::gg(a, b, c, d, w[9], S[24], 0x21e1cde6); /* 25 */
        Self::gg(d, a, b, c, w[14], S[25], 0xc33707d6); /* 26 */
        Self::gg(c, d, a, b, w[3], S[26], 0xf4d50d87); /* 27 */
        Self::gg(b, c, d, a, w[8], S[27], 0x455a14ed); /* 28 */
        Self::gg(a, b, c, d, w[13], S[28], 0xa9e3e905); /* 29 */
        Self::gg(d, a, b, c, w[2], S[29], 0xfcefa3f8); /* 30 */
        Self::gg(c, d, a, b, w[7], S[30], 0x676f02d9); /* 31 */
        Self::gg(b, c, d, a, w[12], S[31], 0x8d2a4c8a); /* 32 */

        /* Round 3 */
        Self::hh(a, b, c, d, w[5], S[32], 0xfffa3942); /* 33 */
        Self::hh(d, a, b, c, w[8], S[33], 0x8771f681); /* 34 */
        Self::hh(c, d, a, b, w[11], S[34], 0x6d9d6122); /* 35 */
        Self::hh(b, c, d, a, w[14], S[35], 0xfde5380c); /* 36 */
        Self::hh(a, b, c, d, w[1], S[36], 0xa4beea44); /* 37 */
        Self::hh(d, a, b, c, w[4], S[37], 0x4bdecfa9); /* 38 */
        Self::hh(c, d, a, b, w[7], S[38], 0xf6bb4b60); /* 39 */
        Self::hh(b, c, d, a, w[10], S[39], 0xbebfbc70); /* 40 */
        Self::hh(a, b, c, d, w[13], S[40], 0x289b7ec6); /* 41 */
        Self::hh(d, a, b, c, w[0], S[41], 0xeaa127fa); /* 42 */
        Self::hh(c, d, a, b, w[3], S[42], 0xd4ef3085); /* 43 */
        Self::hh(b, c, d, a, w[6], S[43], 0x4881d05); /* 44 */
        Self::hh(a, b, c, d, w[9], S[44], 0xd9d4d039); /* 45 */
        Self::hh(d, a, b, c, w[12], S[45], 0xe6db99e5); /* 46 */
        Self::hh(c, d, a, b, w[15], S[46], 0x1fa27cf8); /* 47 */
        Self::hh(b, c, d, a, w[2], S[47], 0xc4ac5665); /* 48 */

        /* Round 4 */
        Self::ii(a, b, c, d, w[0], S[48], 0xf4292244); /* 49 */
        Self::ii(d, a, b, c, w[7], S[49], 0x432aff97); /* 50 */
        Self::ii(c, d, a, b, w[14], S[50], 0xab9423a7); /* 51 */
        Self::ii(b, c, d, a, w[5], S[51], 0xfc93a039); /* 52 */
        Self::ii(a, b, c, d, w[12], S[52], 0x655b59c3); /* 53 */
        Self::ii(d, a, b, c, w[3], S[53], 0x8f0ccc92); /* 54 */
        Self::ii(c, d, a, b, w[10], S[54], 0xffeff47d); /* 55 */
        Self::ii(b, c, d, a, w[1], S[55], 0x85845dd1); /* 56 */
        Self::ii(a, b, c, d, w[8], S[56], 0x6fa87e4f); /* 57 */
        Self::ii(d, a, b, c, w[15], S[57], 0xfe2ce6e0); /* 58 */
        Self::ii(c, d, a, b, w[6], S[58], 0xa3014314); /* 59 */
        Self::ii(b, c, d, a, w[13], S[59], 0x4e0811a1); /* 60 */
        Self::ii(a, b, c, d, w[4], S[60], 0xf7537e82); /* 61 */
        Self::ii(d, a, b, c, w[11], S[61], 0xbd3af235); /* 62 */
        Self::ii(c, d, a, b, w[2], S[62], 0x2ad7d2bb); /* 63 */
        Self::ii(b, c, d, a, w[9], S[63], 0xeb86d391); /* 64 */
        //        for i in 0..64 {
        //            let mut f: u32;
        //            let g: u32;
        //            if i <= 15 {
        //                f = (*b & *c) | (!(*b) & *d);
        //                g = i;
        //            } else if 16 <= i && i <= 31 {
        //                f = (*d & *b) | (!*d & *c);
        //                g = ((5 * i) + 1) % 16;
        //            } else if 32 <= i && i <= 47 {
        //                f = *b ^ *c ^ *d;
        //                g = ((3 * i) + 5) % 16;
        //            } else {
        //                f = *c ^ (*b | (!*d));
        //                g = (7 * i) % 16;
        //            }
        //            f = f.wrapping_add(*a).wrapping_add(K[i as usize]).wrapping_add(w[g as usize]); // m[g] must be a 32-bit block
        //            *a = *d;
        //            *d = *c;
        //            *c = *b;
        //            *b = b.wrapping_add(left_rotate(f, S[i as usize]));
        //        }
    }

    fn hash_algo(&mut self) {
        let [mut a, mut b, mut c, mut d] = &self.hashes.clone();
        Self::compression(&self.chunk, &mut a, &mut b, &mut c, &mut d);
        self.hashes[0] = a.wrapping_add(self.hashes[0]);
        self.hashes[1] = b.wrapping_add(self.hashes[1]);
        self.hashes[2] = c.wrapping_add(self.hashes[2]);
        self.hashes[3] = d.wrapping_add(self.hashes[3]);
    }

    fn get_hash_string(&self) -> String {
        let mut out = String::new();
        for h in &self.hashes {
            write!(
                &mut out,
                "{:02x}{:02x}{:02x}{:02x}",
                h & 0xff,
                (h >> 8) & 0xff,
                (h >> 16) & 0xff,
                (h >> 24) & 0xff,
            )
            .unwrap();
        }
        out
    }

    #[inline(always)]
    fn f(x: &u32, y: &u32, z: &u32) -> u32 {
        (x & y) | (!x & z)
    }
    #[inline(always)]
    fn g(x: &u32, y: &u32, z: &u32) -> u32 {
        (x & z) | (y & !z)
    }
    #[inline(always)]
    fn h(x: &u32, y: &u32, z: &u32) -> u32 {
        x ^ y ^ z
    }
    #[inline(always)]
    fn i(x: &u32, y: &u32, z: &u32) -> u32 {
        y ^ (x | !z)
    }
    #[inline(always)]
    fn ff(a: &mut u32, b: &u32, c: &u32, d: &u32, x: u32, s: usize, ac: u32) {
        *a = a
            .wrapping_add(Self::f(b, c, d))
            .wrapping_add(x)
            .wrapping_add(ac);
        *a = left_rotate(*a, s);
        *a = a.wrapping_add(*b);
    }
    #[inline(always)]
    fn gg(a: &mut u32, b: &u32, c: &u32, d: &u32, x: u32, s: usize, ac: u32) {
        *a = a
            .wrapping_add(Self::g(b, c, d))
            .wrapping_add(x)
            .wrapping_add(ac);
        *a = left_rotate(*a, s);
        *a = a.wrapping_add(*b);
    }
    #[inline(always)]
    fn hh(a: &mut u32, b: &u32, c: &u32, d: &u32, x: u32, s: usize, ac: u32) {
        *a = a
            .wrapping_add(Self::h(b, c, d))
            .wrapping_add(x)
            .wrapping_add(ac);
        *a = left_rotate(*a, s);
        *a = a.wrapping_add(*b);
    }
    #[inline(always)]
    fn ii(a: &mut u32, b: &u32, c: &u32, d: &u32, x: u32, s: usize, ac: u32) {
        *a = a
            .wrapping_add(Self::i(b, c, d))
            .wrapping_add(x)
            .wrapping_add(ac);
        *a = left_rotate(*a, s);
        *a = a.wrapping_add(*b);
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
                let mut data = buffer[..n].to_vec();
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
            // println!("INFO: i: {i}, data:{:?}", &self.algo.data[i..(i + BUFFER_SIZE_U8)]);
            MD5::copy_buf_u8_to_u32(&self.algo.data, &mut self.algo.chunk, i);
            self.algo.hash_algo();
        }
        self.algo.get_hash_string()
    }
}
