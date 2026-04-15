use crate::{buffer::BlockBuffer, digest::Digest, encoding::DigestBytes};

use super::sha2::{compress_sha256, digest_from_u32_state};

const INITIAL_STATE: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

#[derive(Clone, Debug)]
pub struct Sha256 {
    state: [u32; 8],
    buffer: BlockBuffer<64, 8, true>,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
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

impl Digest for Sha256 {
    const OUTPUT_SIZE: usize = 32;

    fn update(&mut self, data: &[u8]) {
        let state = &mut self.state;
        self.buffer
            .update(data, |block| compress_sha256(state, block));
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
        self.buffer.finalize(|block| compress_sha256(state, block));
        digest_from_u32_state(&self.state, Self::OUTPUT_SIZE)
    }
}
