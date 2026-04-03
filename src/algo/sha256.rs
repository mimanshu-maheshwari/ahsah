use crate::traits::HashAlgorithm;
use crate::utils::{big_sigma, ch, maj, small_sigma};

const MESSAGE_SCHEDULE_SIZE: usize = 64;
const BLOCK_SIZE: usize = 64;
const HASH_SIZE_U32: usize = 8;

const H: [u32; HASH_SIZE_U32] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
    0x5be0cd19,
];

const K: [u32; MESSAGE_SCHEDULE_SIZE] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
    0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
    0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
    0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
    0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2,
];

#[derive(Debug)]
pub struct Sha256 {
    data: Vec<u8>,
    hashes: [u32; HASH_SIZE_U32],
    bytes_len: usize,
}

impl HashAlgorithm for Sha256 {
    const BLOCK_SIZE: usize = BLOCK_SIZE;
    const HASH_SIZE: usize = 32;
    const LENGTH_SIZE: usize = 8;
    const LENGTH_IS_BIG_ENDIAN: bool = true;

    fn new() -> Self {
        Self {
            data: Vec::new(),
            hashes: H,
            bytes_len: 0,
        }
    }

    fn data_mut(&mut self) -> &mut Vec<u8> {
        &mut self.data
    }

    fn data(&self) -> &[u8] {
        &self.data
    }

    fn bytes_len(&self) -> usize {
        self.bytes_len
    }

    fn set_bytes_len(&mut self, len: usize) {
        self.bytes_len = len;
    }

    fn process_block(&mut self, block: &[u8]) {
        // Decode 64 bytes into 16 u32 words (big-endian)
        let mut chunk = [0u32; 16];
        for (i, c) in chunk.iter_mut().enumerate() {
            let offset = i * 4;
            *c = u32::from_be_bytes([
                block[offset],
                block[offset + 1],
                block[offset + 2],
                block[offset + 3],
            ]);
        }

        // Message schedule
        let mut w = [0u32; MESSAGE_SCHEDULE_SIZE];
        w[..16].copy_from_slice(&chunk);
        for i in 16..MESSAGE_SCHEDULE_SIZE {
            let s0 = small_sigma(w[i - 15], (7, 18, 3));
            let s1 = small_sigma(w[i - 2], (17, 19, 10));
            w[i] = s0
                .wrapping_add(s1)
                .wrapping_add(w[i - 16])
                .wrapping_add(w[i - 7]);
        }

        // Compression
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.hashes;
        for i in 0..MESSAGE_SCHEDULE_SIZE {
            let sum1 = big_sigma(e, (6, 11, 25));
            let ch_val = ch(e, f, g);
            let temp1 = h
                .wrapping_add(sum1)
                .wrapping_add(ch_val)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let sum0 = big_sigma(a, (2, 13, 22));
            let maj_val = maj(a, b, c);
            let temp2 = sum0.wrapping_add(maj_val);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        self.hashes[0] = a.wrapping_add(self.hashes[0]);
        self.hashes[1] = b.wrapping_add(self.hashes[1]);
        self.hashes[2] = c.wrapping_add(self.hashes[2]);
        self.hashes[3] = d.wrapping_add(self.hashes[3]);
        self.hashes[4] = e.wrapping_add(self.hashes[4]);
        self.hashes[5] = f.wrapping_add(self.hashes[5]);
        self.hashes[6] = g.wrapping_add(self.hashes[6]);
        self.hashes[7] = h.wrapping_add(self.hashes[7]);
    }

    fn encode_length(buf: &mut Vec<u8>, total_bits: u128) {
        buf.extend_from_slice(&(total_bits as u64).to_be_bytes());
    }

    fn hash_string(&self) -> String {
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
