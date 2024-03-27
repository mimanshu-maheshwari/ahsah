use std::io::{BufReader, Read};

/// Message buffer size in bytes
const BUFFER_SIZE_U8: usize = 64usize;
#[allow(unused)]
const BUFFER_SIZE_BITS: usize = 512usize;

/// Hash size in 4bytes
const HASH_SIZE_U32: usize = 8usize;
#[allow(unused)]
const HASH_SIZE_BITS: usize = 256usize;

pub fn hash(msg : &[u8]) -> Option<()> {
    let msg_len: usize = msg.len();
    if msg_len == 0 {
        return None;
    }
    let mut buf_reader: BufReader<_> = BufReader::new(msg);
    let num_of_blocks: usize = ((msg_len as f64) / BUFFER_SIZE_U8 as f64).ceil() as usize;

    let mut _hash_value: [u32; HASH_SIZE_U32]= [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];

    let mut _pref_buf: [u8; BUFFER_SIZE_U8] = [0; BUFFER_SIZE_U8]; 
    let mut msg_block_buf: [u8; BUFFER_SIZE_U8] = [0; BUFFER_SIZE_U8];

    for i in 0..num_of_blocks {
        let l = buf_reader.read(&mut msg_block_buf).expect(&format!("ERROR: Unable to read message block {i} in to buffer"));
        // padding the msg if the length of message read is less than buffer size. 
        let k = ((l * 8) + 1) % BUFFER_SIZE_BITS;
        println!("{i}: bits read: {l}, remainging bits: {k}");
    }
    Some(())
}

