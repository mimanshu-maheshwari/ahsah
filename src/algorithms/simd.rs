#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use std::arch::is_x86_feature_detected;

#[cfg(target_arch = "x86")]
use std::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub(crate) fn decode_be_u32x16(block: &[u8; 64]) -> Option<[u32; 16]> {
    if is_x86_feature_detected!("ssse3") {
        Some(unsafe { decode_be_u32x16_ssse3(block) })
    } else {
        None
    }
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
pub(crate) fn decode_be_u32x16(_block: &[u8; 64]) -> Option<[u32; 16]> {
    None
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub(crate) fn decode_be_u64x16(block: &[u8; 128]) -> Option<[u64; 16]> {
    if is_x86_feature_detected!("ssse3") {
        Some(unsafe { decode_be_u64x16_ssse3(block) })
    } else {
        None
    }
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
pub(crate) fn decode_be_u64x16(_block: &[u8; 128]) -> Option<[u64; 16]> {
    None
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub(crate) fn decode_le_u32x16(block: &[u8; 64]) -> Option<[u32; 16]> {
    if is_x86_feature_detected!("sse2") {
        Some(unsafe { decode_le_u32x16_sse2(block) })
    } else {
        None
    }
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
pub(crate) fn decode_le_u32x16(_block: &[u8; 64]) -> Option<[u32; 16]> {
    None
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "ssse3")]
unsafe fn decode_be_u32x16_ssse3(block: &[u8; 64]) -> [u32; 16] {
    let mask = _mm_set_epi8(12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3);
    let mut swapped = [0u8; 64];

    for lane in 0..4 {
        let input = unsafe { _mm_loadu_si128(block.as_ptr().add(lane * 16) as *const __m128i) };
        let output = _mm_shuffle_epi8(input, mask);
        unsafe {
            _mm_storeu_si128(swapped.as_mut_ptr().add(lane * 16) as *mut __m128i, output);
        }
    }

    let mut words = [0u32; 16];
    for (index, word) in words.iter_mut().enumerate() {
        let offset = index * 4;
        *word = u32::from_ne_bytes([
            swapped[offset],
            swapped[offset + 1],
            swapped[offset + 2],
            swapped[offset + 3],
        ]);
    }
    words
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "ssse3")]
unsafe fn decode_be_u64x16_ssse3(block: &[u8; 128]) -> [u64; 16] {
    let mask = _mm_set_epi8(8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7);
    let mut swapped = [0u8; 128];

    for lane in 0..8 {
        let input = unsafe { _mm_loadu_si128(block.as_ptr().add(lane * 16) as *const __m128i) };
        let output = _mm_shuffle_epi8(input, mask);
        unsafe {
            _mm_storeu_si128(swapped.as_mut_ptr().add(lane * 16) as *mut __m128i, output);
        }
    }

    let mut words = [0u64; 16];
    for (index, word) in words.iter_mut().enumerate() {
        let offset = index * 8;
        *word = u64::from_ne_bytes([
            swapped[offset],
            swapped[offset + 1],
            swapped[offset + 2],
            swapped[offset + 3],
            swapped[offset + 4],
            swapped[offset + 5],
            swapped[offset + 6],
            swapped[offset + 7],
        ]);
    }
    words
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "sse2")]
unsafe fn decode_le_u32x16_sse2(block: &[u8; 64]) -> [u32; 16] {
    let mut copied = [0u8; 64];

    for lane in 0..4 {
        let input = unsafe { _mm_loadu_si128(block.as_ptr().add(lane * 16) as *const __m128i) };
        unsafe {
            _mm_storeu_si128(copied.as_mut_ptr().add(lane * 16) as *mut __m128i, input);
        }
    }

    let mut words = [0u32; 16];
    for (index, word) in words.iter_mut().enumerate() {
        let offset = index * 4;
        *word = u32::from_le_bytes([
            copied[offset],
            copied[offset + 1],
            copied[offset + 2],
            copied[offset + 3],
        ]);
    }
    words
}
