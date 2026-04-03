pub trait HashAlgorithm: Sized {
    /// Bytes per block (64 for SHA-256/MD5, 128 for SHA-512)
    const BLOCK_SIZE: usize;
    /// Output bytes (32, 64, 16)
    const HASH_SIZE: usize;
    /// Length field bytes (8, 16, 8)
    const LENGTH_SIZE: usize;
    /// true for SHA, false for MD5
    const LENGTH_IS_BIG_ENDIAN: bool;

    fn new() -> Self;
    fn data_mut(&mut self) -> &mut Vec<u8>;
    fn data(&self) -> &[u8];
    fn bytes_len(&self) -> usize;
    fn set_bytes_len(&mut self, len: usize);

    /// Process one block of BLOCK_SIZE bytes (decode + compress)
    fn process_block(&mut self, block: &[u8]);

    /// Encode the total bit length into LENGTH_SIZE bytes and append to buf
    fn encode_length(buf: &mut Vec<u8>, total_bits: u128);

    /// Return final hex hash string
    fn hash_string(&self) -> String;

    /// Append padding to buf using total_bits as the message length in bits for the length field
    fn append_padding(buf: &mut Vec<u8>, total_bits: usize) {
        buf.push(0x80);
        let current_len = buf.len();
        let k = (Self::BLOCK_SIZE - ((current_len + Self::LENGTH_SIZE) % Self::BLOCK_SIZE))
            % Self::BLOCK_SIZE;
        buf.resize(current_len + k, 0);
        Self::encode_length(buf, total_bits as u128);
    }
}
