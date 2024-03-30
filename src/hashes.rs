pub trait AhsahHasher {
    fn digest(&mut self, data: &[u8]);
    fn finish(&mut self) -> String;
}
