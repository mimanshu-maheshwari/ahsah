use std::io::Read;

pub trait AhsahHasher {
    fn digest(&mut self, data: &[u8]);
    fn finish(&mut self) -> String;

    fn hash_bufferd<R: Read>(&mut self, handle: &mut R) -> String;
}
