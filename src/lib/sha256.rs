use std::io::{BufReader, Read};

/// Message buffer size in bytes
const BUFFER_SIZE_BITS: usize = 512usize;
const BUFFER_SIZE_U8: usize = BUFFER_SIZE_BITS / 8;
#[allow(unused)]
const BUFFER_SIZE_U32: usize = BUFFER_SIZE_BITS / 32;

const LENGTH_VALUE_PADDING_SIZE_BITS: usize = 64;
const BUFFER_SIZE_WITHOUT_LENGTH_BITS: usize = BUFFER_SIZE_BITS - LENGTH_VALUE_PADDING_SIZE_BITS; 

/// Hash size in 4bytes
const HASH_SIZE_BITS: usize = 256usize;
const HASH_SIZE_U32: usize = HASH_SIZE_BITS / 32;

pub fn hash(msg : &[u8]) -> Option<()> {
    let msg_len: usize = msg.len();
    if msg_len == 0 {
        return None;
    }
    let mut buf_reader: BufReader<_> = BufReader::new(msg);
    let num_of_blocks: usize = ((msg_len as f64) / BUFFER_SIZE_U8 as f64).ceil() as usize;

    let mut _hash_value: [u32; HASH_SIZE_U32] = 
        [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 
         0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];

    let mut _prev_block_buf: [u32; BUFFER_SIZE_U8] = 
        [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
         0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
         0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
         0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
         0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
         0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
         0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
         0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
         0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
         0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
         0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
         0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
         0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
         0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
         0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
         0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];

    let mut cur_block_buf: [u32; BUFFER_SIZE_U32] = [0; BUFFER_SIZE_U32]; 
    let mut temp_cur_block_buf: [u8; BUFFER_SIZE_U8] = [0; BUFFER_SIZE_U8];

    for i in 0..num_of_blocks {
        let l = buf_reader.read(&mut temp_cur_block_buf).expect(&format!("ERROR: Unable to read message block {i} in to buffer"));
        copy_buf_u8_to_u32(&mut temp_cur_block_buf, &mut cur_block_buf);
        // padding the msg if the length of message read is less than buffer size. 
        if l != BUFFER_SIZE_U8 {
            let l = l * 8; 
            let k = BUFFER_SIZE_WITHOUT_LENGTH_BITS - (l + 1) % BUFFER_SIZE_BITS;
            println!("{i}: bits read: {l}, remainging bits: {k}");
            println!("Buffer u8:");
            for i in 0..temp_cur_block_buf.len() {
                print!("0x{val:08x} ", val = temp_cur_block_buf[i]);
            }
            println!("\nBuffer u32:");
            for i in 0..cur_block_buf.len() {
                print!("0x{val:08x} ", val = cur_block_buf[i]);
            }
            println!("");
            
        }
    }
    Some(())
}

fn copy_buf_u8_to_u32(u8_block: &[u8; BUFFER_SIZE_U8], u32_block: &mut [u32; BUFFER_SIZE_U32]) {
    for i in 0..BUFFER_SIZE_U32 {
        u32_block[i] = 
            ((u8_block[i * 4]     as u32) << 24) |
            ((u8_block[i * 4 + 1] as u32) << 16) | 
            ((u8_block[i * 4 + 2] as u32) << 8 ) | 
              u8_block[i * 4 + 3] as u32;
    }
}


