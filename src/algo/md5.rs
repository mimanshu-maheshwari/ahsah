use crate::traits::HashAlgorithm;
use crate::utils::left_rotate;
use std::fmt::Write;

const BLOCK_SIZE: usize = 64;
const HASH_SIZE_U32: usize = 4;
const MESSAGE_SCHEDULE_SIZE: usize = 16;

// s specifies the per-round shift amounts
const S: [usize; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
    9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
    15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

const H: [u32; HASH_SIZE_U32] = [
    0x67452301, // A
    0xefcdab89, // B
    0x98badcfe, // C
    0x10325476, // D
];

#[derive(Copy, Clone)]
struct State {
    a: u32,
    b: u32,
    c: u32,
    d: u32,
}

impl From<[u32; HASH_SIZE_U32]> for State {
    fn from(value: [u32; HASH_SIZE_U32]) -> Self {
        Self {
            a: value[0],
            b: value[1],
            c: value[2],
            d: value[3],
        }
    }
}

#[derive(Debug)]
pub struct MD5 {
    data: Vec<u8>,
    hashes: [u32; HASH_SIZE_U32],
    bytes_len: usize,
}

impl MD5 {
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

    fn compress_scaler_rounds(w: &[u32; MESSAGE_SCHEDULE_SIZE], st: &mut State) {
        let (mut a, mut b, mut c, mut d) = (st.a, st.b, st.c, st.d);

        /* Round 1 */
        Self::ff(&mut a, &b, &c, &d, w[0], S[0], 0xd76aa478);
        Self::ff(&mut d, &a, &b, &c, w[1], S[1], 0xe8c7b756);
        Self::ff(&mut c, &d, &a, &b, w[2], S[2], 0x242070db);
        Self::ff(&mut b, &c, &d, &a, w[3], S[3], 0xc1bdceee);
        Self::ff(&mut a, &b, &c, &d, w[4], S[4], 0xf57c0faf);
        Self::ff(&mut d, &a, &b, &c, w[5], S[5], 0x4787c62a);
        Self::ff(&mut c, &d, &a, &b, w[6], S[6], 0xa8304613);
        Self::ff(&mut b, &c, &d, &a, w[7], S[7], 0xfd469501);
        Self::ff(&mut a, &b, &c, &d, w[8], S[8], 0x698098d8);
        Self::ff(&mut d, &a, &b, &c, w[9], S[9], 0x8b44f7af);
        Self::ff(&mut c, &d, &a, &b, w[10], S[10], 0xffff5bb1);
        Self::ff(&mut b, &c, &d, &a, w[11], S[11], 0x895cd7be);
        Self::ff(&mut a, &b, &c, &d, w[12], S[12], 0x6b901122);
        Self::ff(&mut d, &a, &b, &c, w[13], S[13], 0xfd987193);
        Self::ff(&mut c, &d, &a, &b, w[14], S[14], 0xa679438e);
        Self::ff(&mut b, &c, &d, &a, w[15], S[15], 0x49b40821);

        /* Round 2 */
        Self::gg(&mut a, &b, &c, &d, w[1], S[16], 0xf61e2562);
        Self::gg(&mut d, &a, &b, &c, w[6], S[17], 0xc040b340);
        Self::gg(&mut c, &d, &a, &b, w[11], S[18], 0x265e5a51);
        Self::gg(&mut b, &c, &d, &a, w[0], S[19], 0xe9b6c7aa);
        Self::gg(&mut a, &b, &c, &d, w[5], S[20], 0xd62f105d);
        Self::gg(&mut d, &a, &b, &c, w[10], S[21], 0x2441453);
        Self::gg(&mut c, &d, &a, &b, w[15], S[22], 0xd8a1e681);
        Self::gg(&mut b, &c, &d, &a, w[4], S[23], 0xe7d3fbc8);
        Self::gg(&mut a, &b, &c, &d, w[9], S[24], 0x21e1cde6);
        Self::gg(&mut d, &a, &b, &c, w[14], S[25], 0xc33707d6);
        Self::gg(&mut c, &d, &a, &b, w[3], S[26], 0xf4d50d87);
        Self::gg(&mut b, &c, &d, &a, w[8], S[27], 0x455a14ed);
        Self::gg(&mut a, &b, &c, &d, w[13], S[28], 0xa9e3e905);
        Self::gg(&mut d, &a, &b, &c, w[2], S[29], 0xfcefa3f8);
        Self::gg(&mut c, &d, &a, &b, w[7], S[30], 0x676f02d9);
        Self::gg(&mut b, &c, &d, &a, w[12], S[31], 0x8d2a4c8a);

        /* Round 3 */
        Self::hh(&mut a, &b, &c, &d, w[5], S[32], 0xfffa3942);
        Self::hh(&mut d, &a, &b, &c, w[8], S[33], 0x8771f681);
        Self::hh(&mut c, &d, &a, &b, w[11], S[34], 0x6d9d6122);
        Self::hh(&mut b, &c, &d, &a, w[14], S[35], 0xfde5380c);
        Self::hh(&mut a, &b, &c, &d, w[1], S[36], 0xa4beea44);
        Self::hh(&mut d, &a, &b, &c, w[4], S[37], 0x4bdecfa9);
        Self::hh(&mut c, &d, &a, &b, w[7], S[38], 0xf6bb4b60);
        Self::hh(&mut b, &c, &d, &a, w[10], S[39], 0xbebfbc70);
        Self::hh(&mut a, &b, &c, &d, w[13], S[40], 0x289b7ec6);
        Self::hh(&mut d, &a, &b, &c, w[0], S[41], 0xeaa127fa);
        Self::hh(&mut c, &d, &a, &b, w[3], S[42], 0xd4ef3085);
        Self::hh(&mut b, &c, &d, &a, w[6], S[43], 0x4881d05);
        Self::hh(&mut a, &b, &c, &d, w[9], S[44], 0xd9d4d039);
        Self::hh(&mut d, &a, &b, &c, w[12], S[45], 0xe6db99e5);
        Self::hh(&mut c, &d, &a, &b, w[15], S[46], 0x1fa27cf8);
        Self::hh(&mut b, &c, &d, &a, w[2], S[47], 0xc4ac5665);

        /* Round 4 */
        Self::ii(&mut a, &b, &c, &d, w[0], S[48], 0xf4292244);
        Self::ii(&mut d, &a, &b, &c, w[7], S[49], 0x432aff97);
        Self::ii(&mut c, &d, &a, &b, w[14], S[50], 0xab9423a7);
        Self::ii(&mut b, &c, &d, &a, w[5], S[51], 0xfc93a039);
        Self::ii(&mut a, &b, &c, &d, w[12], S[52], 0x655b59c3);
        Self::ii(&mut d, &a, &b, &c, w[3], S[53], 0x8f0ccc92);
        Self::ii(&mut c, &d, &a, &b, w[10], S[54], 0xffeff47d);
        Self::ii(&mut b, &c, &d, &a, w[1], S[55], 0x85845dd1);
        Self::ii(&mut a, &b, &c, &d, w[8], S[56], 0x6fa87e4f);
        Self::ii(&mut d, &a, &b, &c, w[15], S[57], 0xfe2ce6e0);
        Self::ii(&mut c, &d, &a, &b, w[6], S[58], 0xa3014314);
        Self::ii(&mut b, &c, &d, &a, w[13], S[59], 0x4e0811a1);
        Self::ii(&mut a, &b, &c, &d, w[4], S[60], 0xf7537e82);
        Self::ii(&mut d, &a, &b, &c, w[11], S[61], 0xbd3af235);
        Self::ii(&mut c, &d, &a, &b, w[2], S[62], 0x2ad7d2bb);
        Self::ii(&mut b, &c, &d, &a, w[9], S[63], 0xeb86d391);

        st.a = a;
        st.b = b;
        st.c = c;
        st.d = d;
    }
}

impl HashAlgorithm for MD5 {
    const BLOCK_SIZE: usize = BLOCK_SIZE;
    const HASH_SIZE: usize = 16;
    const LENGTH_SIZE: usize = 8;
    const LENGTH_IS_BIG_ENDIAN: bool = false;

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
        // Decode 64 bytes into 16 u32 words (little-endian)
        let mut chunk = [0u32; MESSAGE_SCHEDULE_SIZE];
        for (dst, src) in chunk
            .iter_mut()
            .zip(block[..BLOCK_SIZE].chunks_exact(4))
        {
            *dst = u32::from_le_bytes(src.try_into().unwrap());
        }

        let mut state = State::from(self.hashes);
        Self::compress_scaler_rounds(&chunk, &mut state);
        self.hashes[0] = state.a.wrapping_add(self.hashes[0]);
        self.hashes[1] = state.b.wrapping_add(self.hashes[1]);
        self.hashes[2] = state.c.wrapping_add(self.hashes[2]);
        self.hashes[3] = state.d.wrapping_add(self.hashes[3]);
    }

    fn encode_length(buf: &mut Vec<u8>, total_bits: u128) {
        buf.extend_from_slice(&(total_bits as u64).to_le_bytes());
    }

    fn hash_string(&self) -> String {
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
}
