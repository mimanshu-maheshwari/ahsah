use crate::{buffer::BlockBuffer, digest::Digest, encoding::DigestBytes};

use super::sha2::{compress_sha512, digest_from_u64_state};

const INITIAL_STATE: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

#[derive(Clone, Debug)]
pub struct Sha512 {
    state: [u64; 8],
    buffer: BlockBuffer<128, 16, true>,
}

impl Default for Sha512 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha512 {
    pub fn new() -> Self {
        Self {
            state: INITIAL_STATE,
            buffer: BlockBuffer::new(),
        }
    }

    pub fn digest(data: &[u8]) -> DigestBytes {
        <Self as Digest>::digest(data)
    }

    pub fn finalize_hex(self) -> String {
        <Self as Digest>::finalize_hex(self)
    }
}

impl Digest for Sha512 {
    const OUTPUT_SIZE: usize = 64;

    fn update(&mut self, data: &[u8]) {
        let state = &mut self.state;
        self.buffer
            .update(data, |block| compress_sha512(state, block));
    }

    fn input_size(&self) -> u128 {
        self.buffer.message_len()
    }

    fn reset(&mut self) {
        self.state = INITIAL_STATE;
        self.buffer.reset();
    }

    fn finalize(mut self) -> DigestBytes {
        let state = &mut self.state;
        self.buffer.finalize(|block| compress_sha512(state, block));
        digest_from_u64_state(&self.state, Self::OUTPUT_SIZE)
    }
}
