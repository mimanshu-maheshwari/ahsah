use crate::{buffer::BlockBuffer, digest::Digest, encoding::DigestBytes};

use super::sha2::{compress_sha256, digest_from_u32_state};

const INITIAL_STATE: [u32; 8] = [
    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
];

#[derive(Clone, Debug)]
pub struct Sha224 {
    state: [u32; 8],
    buffer: BlockBuffer<64, 8, true>,
}

impl Default for Sha224 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha224 {
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

impl Digest for Sha224 {
    const OUTPUT_SIZE: usize = 28;

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
