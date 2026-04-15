use crate::{buffer::BlockBuffer, digest::Digest, encoding::DigestBytes};

const INITIAL_STATE: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];

const SHIFT_AMOUNTS: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15,
    21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

const TABLE: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

#[derive(Clone, Debug)]
pub struct Md5 {
    state: [u32; 4],
    buffer: BlockBuffer<64, 8, false>,
}

#[allow(non_camel_case_types)]
pub type MD5 = Md5;

impl Default for Md5 {
    fn default() -> Self {
        Self::new()
    }
}

impl Md5 {
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

impl Digest for Md5 {
    const OUTPUT_SIZE: usize = 16;

    fn update(&mut self, data: &[u8]) {
        let state = &mut self.state;
        self.buffer.update(data, |block| compress_md5(state, block));
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
        self.buffer.finalize(|block| compress_md5(state, block));

        let mut bytes = Vec::with_capacity(Self::OUTPUT_SIZE);
        for word in &self.state {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        DigestBytes::new(bytes)
    }
}

fn compress_md5(state: &mut [u32; 4], block: &[u8; 64]) {
    let words = decode_le_u32_words(block);
    let [mut a, mut b, mut c, mut d] = *state;

    for round in 0..64 {
        let (f, g) = match round {
            0..=15 => ((b & c) | (!b & d), round),
            16..=31 => ((d & b) | (!d & c), (5 * round + 1) % 16),
            32..=47 => (b ^ c ^ d, (3 * round + 5) % 16),
            _ => (c ^ (b | !d), (7 * round) % 16),
        };

        let next = a
            .wrapping_add(f)
            .wrapping_add(TABLE[round])
            .wrapping_add(words[g]);
        let rotated = next.rotate_left(SHIFT_AMOUNTS[round]);

        a = d;
        d = c;
        c = b;
        b = b.wrapping_add(rotated);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
}

fn decode_le_u32_words(block: &[u8; 64]) -> [u32; 16] {
    #[cfg(feature = "simd")]
    {
        if let Some(words) = super::simd::decode_le_u32x16(block) {
            return words;
        }
    }

    let mut words = [0u32; 16];
    for (word, chunk) in words.iter_mut().zip(block.chunks_exact(4)) {
        *word = u32::from_le_bytes(chunk.try_into().expect("chunk has 4 bytes"));
    }
    words
}

#[cfg(all(test, feature = "simd"))]
pub(crate) fn decode_le_u32_words_scalar(block: &[u8; 64]) -> [u32; 16] {
    let mut words = [0u32; 16];
    for (word, chunk) in words.iter_mut().zip(block.chunks_exact(4)) {
        *word = u32::from_le_bytes(chunk.try_into().expect("chunk has 4 bytes"));
    }
    words
}

#[cfg(all(test, feature = "simd"))]
mod tests {
    use super::{decode_le_u32_words, decode_le_u32_words_scalar};

    #[test]
    fn md5_word_decode_matches_scalar() {
        let mut block = [0u8; 64];
        for (index, byte) in block.iter_mut().enumerate() {
            *byte = 255 - index as u8;
        }
        assert_eq!(
            decode_le_u32_words_scalar(&block),
            decode_le_u32_words(&block)
        );
    }
}
