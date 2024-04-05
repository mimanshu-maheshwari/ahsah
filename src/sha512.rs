use super::hashes::{AhsahBufferedHasher, AhsahHasher};
use super::utils::{ch, maj, sigma_0, sigma_1, sum_0, sum_1, k_value};
use std::io::Read;

/// Message buffer size in bits
const BUFFER_SIZE_BITS: usize = 1024;
/// Message buffer size in bytes
const BUFFER_SIZE_U8: usize = BUFFER_SIZE_BITS / 8;
const BUFFER_SIZE_U64: usize = BUFFER_SIZE_BITS / 64;

const MESSAGE_SCHEDULE_SIZE: usize = 80;

/// Hash size in 4bytes
const HASH_SIZE_BITS: usize = 512;
const HASH_SIZE_U64: usize = HASH_SIZE_BITS / 64;

const LENGTH_VALUE_PADDING_SIZE_BITS: usize = 128;

const H: [u64; HASH_SIZE_U64] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
];

const K: [u64; MESSAGE_SCHEDULE_SIZE] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

#[derive(Debug, Default)]
pub struct Sha512 {
    data: Vec<u8>,
    hashes: [u64; HASH_SIZE_U64],
    chunk: [u64; BUFFER_SIZE_U64],
    bytes_len: usize,

}

impl Sha512 {
    fn compression(
        w: &[u64; MESSAGE_SCHEDULE_SIZE],
        (a, b, c, d, e, f, g, h): (
            &mut u64,
            &mut u64,
            &mut u64,
            &mut u64,
            &mut u64,
            &mut u64,
            &mut u64,
            &mut u64,
        ),
    ) {
        for i in 0..MESSAGE_SCHEDULE_SIZE {
            let sum_1 = sum_1(*e, (14, 18, 41));
            let ch = ch(*e, *f, *g);
            let temp_1 = h
                .wrapping_add(sum_1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let sum_0 = sum_0(*a, (28, 34, 39));
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

    /// will copy the data of u8 vec into a array of u64.
    /// we can assert for u8_block remaining bytes length but it should not fail because we
    /// will be padding the vec before copying the data int buffer block.
    fn copy_buf_u8_to_u64(data: &[u8], block: &mut [u64; BUFFER_SIZE_U64], start: usize) {
        assert!(
            BUFFER_SIZE_U8 <= data.len() - start,
            "Remaining bits in buffer are {val}, Expected {BUFFER_SIZE_U8} bits",
            val = (data.len() - start)
        );
        for i in 0..BUFFER_SIZE_U64 {
            block[i] = (data[start + (i * 8) + 0] as u64) << 56
                | (data[start + (i * 8) + 1] as u64) << 48
                | (data[start + (i * 8) + 2] as u64) << 40
                | (data[start + (i * 8) + 3] as u64) << 32
                | (data[start + (i * 8) + 4] as u64) << 24
                | (data[start + (i * 8) + 5] as u64) << 16
                | (data[start + (i * 8) + 6] as u64) << 8
                | data[start + (i * 8) + 7] as u64;
        }
    }

    fn copy_len_to_buf(temp_block_buf: &mut Vec<u8>, len: usize) {
        let len = len as u128;
        temp_block_buf.push((len >> 120u128) as u8 & 0xff);
        temp_block_buf.push((len >> 112u128) as u8 & 0xff);
        temp_block_buf.push((len >> 104u128) as u8 & 0xff);
        temp_block_buf.push((len >> 96u128) as u8 & 0xff);
        temp_block_buf.push((len >> 88u128) as u8 & 0xff);
        temp_block_buf.push((len >> 80u128) as u8 & 0xff);
        temp_block_buf.push((len >> 72u128) as u8 & 0xff);
        temp_block_buf.push((len >> 64u128) as u8 & 0xff);
        temp_block_buf.push((len >> 56u128) as u8 & 0xff);
        temp_block_buf.push((len >> 48u128) as u8 & 0xff);
        temp_block_buf.push((len >> 40u128) as u8 & 0xff);
        temp_block_buf.push((len >> 32u128) as u8 & 0xff);
        temp_block_buf.push((len >> 24u128) as u8 & 0xff);
        temp_block_buf.push((len >> 16u128) as u8 & 0xff);
        temp_block_buf.push((len >> 8u128) as u8 & 0xff);
        temp_block_buf.push((len >> 0u128) as u8 & 0xff);
    }

    fn hash_algo(&mut self) {
        // initialize registers
        // message schedule array
        let mut w = [0; MESSAGE_SCHEDULE_SIZE];
            w[0..16].copy_from_slice(&self.chunk[..]);
            for i in 16..MESSAGE_SCHEDULE_SIZE {
                let sigma_0 = sigma_0(w[i - 15], (1, 8, 7));
                let sigma_1 = sigma_1(w[i - 2], (19, 61, 6));
                w[i] = sigma_0
                    .wrapping_add(sigma_1)
                    .wrapping_add(w[i - 16])
                    .wrapping_add(w[i - 7]);
            }
            let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.hashes.clone();
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
    fn to_string(&self) -> String {
        format!(
            "{:016x}{:016x}{:016x}{:016x}{:016x}{:016x}{:016x}{:016x}",
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

impl AhsahBufferedHasher for Sha512 {
fn new() -> Self {
        Self {
            data: Vec::new(),
            hashes: H.clone(), 
            chunk: [0; BUFFER_SIZE_U64],
            bytes_len: 0,
        }
    }

    fn len(&self) -> usize {
        self.bytes_len
    }


    fn hash_bufferd(&mut self, handle: &mut dyn Read) -> String {
        let mut buffer = [0; BUFFER_SIZE_U8];
        while let Ok(n) = handle.read(&mut buffer) {
            self.bytes_len += n;
            if n == 0 {
                break;
            } else if n == BUFFER_SIZE_U8 {
                Self::copy_buf_u8_to_u64(&buffer, &mut self.chunk, 0);
                self.hash_algo();
            } else {
                let mut data = Vec::new();
                for d in &buffer[..n] {
                    data.push(*d);
                }
                for i in (0..data.len()).step_by(BUFFER_SIZE_U8) {
                    Self::copy_buf_u8_to_u64(&data, &mut self.chunk, i);
                    Self::add_padding(&mut data, Some(self.bytes_len));
                    self.hash_algo();
                }
            }
        }
        self.to_string()
    }
}


impl AhsahHasher for Sha512 {

    fn new() -> Self {
        Self {
            data: Vec::new(),
            hashes: H.clone(), 
            chunk: [0; BUFFER_SIZE_U64],
            bytes_len: 0,
        }
    }

    fn len(&self) -> usize {
        self.data.len()
    }

    fn digest(&mut self, data: &[u8]) {
        for byte in data {
            self.data.push(byte.clone());
        }
    }

    /// Main hasher function
    fn finish(&mut self) -> String {

        Self::add_padding(&mut self.data, None);

        for i in (0..self.data.len()).step_by(BUFFER_SIZE_U8) {
            Self::copy_buf_u8_to_u64(&self.data, &mut self.chunk, i);
            self.hash_algo();
        }
        self.to_string()
    }
}
