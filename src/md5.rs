use super::hashes::{Generic, Hasher, WithReader, WithoutReader};
use std::marker::PhantomData;
use std::io::Read;

#[derive(Debug)]
pub struct MD5 {
    data: Vec<u8>,
    hashes: [u32; 0],
    chunk: [u32; 0],
    bytes_len: usize,
}

impl Default for MD5 {
    fn default() -> Self {
        Self {
            data: Vec::new(),
            hashes: [0; 0],
            bytes_len: 0,
            chunk: [0; 0],
        }
    }
}

impl MD5 {
    /// create a new instance of hasher
    pub(crate) fn new() -> Self {
        Self {
            data: Vec::new(),
            hashes: [0;0],
            bytes_len: 0,
            chunk: [0; 0],
        }
    }
}

impl Hasher<MD5, Generic> {
    pub fn reader(self) -> Hasher<MD5, WithReader> {
        let hasher: Hasher<MD5, WithReader> = Hasher::<MD5, WithReader> {
            algo: self.algo,
            phantom: PhantomData,
        };
        hasher
    }
    pub fn digester(self) -> Hasher<MD5, WithoutReader> {
        let hasher: Hasher<MD5, WithoutReader> = Hasher::<MD5, WithoutReader> {
            algo: self.algo,
            phantom: PhantomData,
        };
        hasher
    }
}

impl Hasher<MD5, WithReader> {
    /// the length of data that is hashed in bytes
    pub fn consumed_len(&self) -> usize {
        self.algo.bytes_len
    }

    /// hashing algorithm
    pub fn read(&mut self, handle: &mut dyn Read) -> String {
        unimplemented!("Implement the read method in MD5 before using it");
    }
}
impl Hasher<MD5, WithoutReader> {
    pub fn consumed_len(&self) -> usize {
        self.algo.data.len()
    }

    pub fn digest(&mut self, data: &[u8]) {
        for byte in data {
            self.algo.data.push(*byte);
        }
    }

    /// Main hasher function
    pub fn finalize(&mut self) -> String {
        unimplemented!("implement the finalize algo before using it");
    }
}
