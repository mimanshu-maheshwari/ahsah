use std::convert::TryInto;

#[derive(Clone, Debug)]
pub(crate) struct BlockBuffer<
    const BLOCK_SIZE: usize,
    const LENGTH_SIZE: usize,
    const BIG_ENDIAN: bool,
> {
    block: [u8; BLOCK_SIZE],
    len: usize,
    total_len: u128,
}

impl<const BLOCK_SIZE: usize, const LENGTH_SIZE: usize, const BIG_ENDIAN: bool>
    BlockBuffer<BLOCK_SIZE, LENGTH_SIZE, BIG_ENDIAN>
{
    pub(crate) fn new() -> Self {
        Self {
            block: [0u8; BLOCK_SIZE],
            len: 0,
            total_len: 0,
        }
    }

    pub(crate) fn reset(&mut self) {
        self.block = [0u8; BLOCK_SIZE];
        self.len = 0;
        self.total_len = 0;
    }

    pub(crate) fn message_len(&self) -> u128 {
        self.total_len
    }

    pub(crate) fn update<F>(&mut self, mut input: &[u8], mut process_block: F)
    where
        F: FnMut(&[u8; BLOCK_SIZE]),
    {
        self.total_len = self
            .total_len
            .checked_add(input.len() as u128)
            .expect("message length overflow");

        if self.len > 0 {
            let to_copy = (BLOCK_SIZE - self.len).min(input.len());
            self.block[self.len..self.len + to_copy].copy_from_slice(&input[..to_copy]);
            self.len += to_copy;
            input = &input[to_copy..];

            if self.len == BLOCK_SIZE {
                process_block(&self.block);
                self.len = 0;
            }
        }

        for chunk in input.chunks_exact(BLOCK_SIZE) {
            let block: &[u8; BLOCK_SIZE] =
                chunk.try_into().expect("chunk length matches block size");
            process_block(block);
        }

        let remainder = input.len() % BLOCK_SIZE;
        if remainder > 0 {
            let start = input.len() - remainder;
            self.block[..remainder].copy_from_slice(&input[start..]);
            self.len = remainder;
        }
    }

    pub(crate) fn finalize<F>(&mut self, mut process_block: F)
    where
        F: FnMut(&[u8; BLOCK_SIZE]),
    {
        let mut tail = Vec::with_capacity(BLOCK_SIZE * 2);
        tail.extend_from_slice(&self.block[..self.len]);
        tail.push(0x80);

        while (tail.len() + LENGTH_SIZE) % BLOCK_SIZE != 0 {
            tail.push(0);
        }

        let bit_len = self.total_len.checked_mul(8).expect("bit length overflow");
        let length_bytes = if BIG_ENDIAN {
            bit_len.to_be_bytes()
        } else {
            bit_len.to_le_bytes()
        };
        if BIG_ENDIAN {
            tail.extend_from_slice(&length_bytes[16 - LENGTH_SIZE..]);
        } else {
            tail.extend_from_slice(&length_bytes[..LENGTH_SIZE]);
        }

        for chunk in tail.chunks_exact(BLOCK_SIZE) {
            let block: &[u8; BLOCK_SIZE] = chunk
                .try_into()
                .expect("final padded chunk length matches block size");
            process_block(block);
        }
    }
}
