use super::hashes::{AhsahBufferedHasher, AhsahHasher};
use super::utils::{ch, k_value, maj, sigma_0, sigma_1, sum_0, sum_1};
use std::io::prelude::Read;

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

#[derive(Debug, Default)]
pub struct Sha256 {
    data: Vec<u8>,
    hashes: [u32; HASH_SIZE_U32],
    chunk: [u32; BUFFER_SIZE_U32],
    bytes_len: usize,
}

impl Sha256 {
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
        for i in 0..MESSAGE_SCHEDULE_SIZE {
            let sum_1 = sum_1(*e, (6, 11, 25));
            let ch = ch(*e, *f, *g);
            let temp_1 = h
                .wrapping_add(sum_1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let sum_0 = sum_0(*a, (2, 13, 22));
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

    fn copy_len_to_buf(temp_block_buf: &mut Vec<u8>, len: usize) {
        temp_block_buf.push((len >> 56) as u8 );
        temp_block_buf.push((len >> 48) as u8 );
        temp_block_buf.push((len >> 40) as u8 );
        temp_block_buf.push((len >> 32) as u8 );
        temp_block_buf.push((len >> 24) as u8 );
        temp_block_buf.push((len >> 16) as u8 );
        temp_block_buf.push((len >>  8) as u8 );
        temp_block_buf.push((len) as u8 );
    }

    fn hash_algo(&mut self) {
        // initialize registers
        // message schedule array
        let mut w = [0; MESSAGE_SCHEDULE_SIZE];

        w[0..16].copy_from_slice(&self.chunk[..]);
        for i in 16..MESSAGE_SCHEDULE_SIZE {
            let sigma_0 = sigma_0(w[i - 15], (7, 18, 3));
            let sigma_1 = sigma_1(w[i - 2], (17, 19, 10));
            w[i] = sigma_0
                .wrapping_add(sigma_1)
                .wrapping_add(w[i - 16])
                .wrapping_add(w[i - 7]);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = &self.hashes.clone();
        Self::compression(
            &w,
            (
                &mut a, &mut b, &mut c, &mut d, &mut e, &mut f, &mut g, &mut h,
            ),
        );
        self.hashes[0] = a.wrapping_add(self.hashes[0]);
        self.hashes[1] = b.wrapping_add(self.hashes[1]);
        self.hashes[2] = c.wrapping_add(self.hashes[2]);
        self.hashes[3] = d.wrapping_add(self.hashes[3]);
        self.hashes[4] = e.wrapping_add(self.hashes[4]);
        self.hashes[5] = f.wrapping_add(self.hashes[5]);
        self.hashes[6] = g.wrapping_add(self.hashes[6]);
        self.hashes[7] = h.wrapping_add(self.hashes[7]);
    }

    fn get_hash_string(&self) -> String {
        format!(
            "{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}",
            self.hashes[0],
            self.hashes[1],
            self.hashes[2],
            self.hashes[3],
            self.hashes[4],
            self.hashes[5],
            self.hashes[6],
            self.hashes[7]
        )
    }
}

impl AhsahBufferedHasher for Sha256 {
    fn new() -> Self {
        Self {
            data: Vec::new(),
            hashes: H,
            bytes_len: 0,
            chunk: [0; BUFFER_SIZE_U32],
        }
    }

    fn consumed_len(&self) -> usize {
        self.bytes_len
    }   
    fn hash_bufferd(&mut self, handle: &mut dyn Read) -> String {
        let mut buffer = [0; BUFFER_SIZE_U8];
        while let Ok(n) = handle.read(&mut buffer) {
            self.bytes_len += n;
            if n == 0 {
                break;
            } else if n == BUFFER_SIZE_U8 {
                Self::copy_buf_u8_to_u32(&buffer, &mut self.chunk, 0);
                self.hash_algo();
            } else {
                let mut data = Vec::new();
                for d in &buffer[..n] {
                    data.push(*d);
                }
                Self::add_padding(&mut data, Some(self.bytes_len));
                for i in (0..data.len()).step_by(BUFFER_SIZE_U8) {
                    Self::copy_buf_u8_to_u32(&data, &mut self.chunk, i);
                    self.hash_algo();
                }
            }
        }
        self.get_hash_string()
    }
}

impl AhsahHasher for Sha256 {
    fn new() -> Self {
        Self {
            data: Vec::new(),
            hashes: H,
            bytes_len: 0,
            chunk: [0; BUFFER_SIZE_U32],
        }
    }

    fn consumed_len(&self) -> usize {
        self.data.len()
    }

    fn digest(&mut self, data: &[u8]) {
        for byte in data {
            self.data.push(*byte);
        }
    }

    /// Main hasher function
    fn finish(&mut self) -> String {
        Self::add_padding(&mut self.data, None);

        for i in (0..self.data.len()).step_by(BUFFER_SIZE_U8) {
            Self::copy_buf_u8_to_u32(&self.data, &mut self.chunk, i);
            self.hash_algo();
        }
        self.get_hash_string()
    }
}
