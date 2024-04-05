use std::io::Read;

struct Bufferd; 
struct NotBufferd; 

pub trait AhsahHasher {
    fn digest(self: &mut Self, data: &[u8]);
    fn finish(self: &mut Self) -> String;
    fn new() -> Self where Self: Sized;
    fn len(self: &Self) -> usize; 
}

pub trait AhsahBufferedHasher {
    fn new() -> Self where Self: Sized;
    fn hash_bufferd<R: Read>(self: &mut Self, handle: &mut R) -> String;
    fn len(self: &Self) -> usize; 
}
