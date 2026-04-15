use crate::encoding::DigestBytes;

pub trait Digest: Clone + Sized {
    const OUTPUT_SIZE: usize;

    fn update(&mut self, data: &[u8]);
    fn input_size(&self) -> u128;
    fn reset(&mut self);
    fn finalize(self) -> DigestBytes;

    fn finalize_hex(self) -> String {
        self.finalize().to_hex()
    }

    fn digest(data: &[u8]) -> DigestBytes
    where
        Self: Default,
    {
        let mut digest = Self::default();
        digest.update(data);
        digest.finalize()
    }
}
