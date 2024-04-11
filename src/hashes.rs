use std::io::Read;

// struct Bufferd;
// struct NotBufferd;

pub trait Hasher {
    fn digest(&mut self, data: &[u8]);
    fn finish(&mut self) -> String;
    fn new() -> Self
    where
        Self: Sized;
    fn consumed_len(&self) -> usize;
}

pub trait BufferedHasher {
    fn new() -> Self
    where
        Self: Sized;
    fn hash_bufferd(&mut self, handle: &mut dyn Read) -> String;

    fn consumed_len(&self) -> usize;
}
