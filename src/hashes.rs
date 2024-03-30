pub trait AhsahHasher {
    fn digest<T>(&mut self, data: T)
        where T: AsRef<[u8]> + IntoIterator<Item = u8> + Sized + Clone;
    fn finish(&mut self) -> String;
}
