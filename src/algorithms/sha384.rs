use crate::{buffer::BlockBuffer, digest::Digest, encoding::DigestBytes};

use super::sha2::{compress_sha512, digest_from_u64_state};

const INITIAL_STATE: [u64; 8] = [
    0xcbbb9d5dc1059ed8,
    0x629a292a367cd507,
    0x9159015a3070dd17,
    0x152fecd8f70e5939,
    0x67332667ffc00b31,
    0x8eb44a8768581511,
    0xdb0c2e0d64f98fa7,
    0x47b5481dbefa4fa4,
];

#[derive(Clone, Debug)]
pub struct Sha384 {
    state: [u64; 8],
    buffer: BlockBuffer<128, 16, true>,
}

impl Default for Sha384 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha384 {
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

impl Digest for Sha384 {
    const OUTPUT_SIZE: usize = 48;

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
