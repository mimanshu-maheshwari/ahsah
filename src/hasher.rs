use std::io::Read;
use std::marker::PhantomData;

use crate::algo::md5::MD5;
use crate::algo::sha256::Sha256;
use crate::algo::sha512::Sha512;
use crate::traits::HashAlgorithm;

pub struct WithReader;
pub struct WithoutReader;
pub struct Generic;

pub struct Hasher<T, B> {
    pub(crate) algo: T,
    pub(crate) phantom: PhantomData<B>,
}

pub struct HashBuilder;

impl HashBuilder {
    pub fn sha256() -> Hasher<Sha256, Generic> {
        Hasher {
            algo: Sha256::new(),
            phantom: PhantomData,
        }
    }
    pub fn sha512() -> Hasher<Sha512, Generic> {
        Hasher {
            algo: Sha512::new(),
            phantom: PhantomData,
        }
    }
    pub fn md5() -> Hasher<MD5, Generic> {
        Hasher {
            algo: MD5::new(),
            phantom: PhantomData,
        }
    }
}

impl<T: HashAlgorithm> Hasher<T, Generic> {
    pub fn reader(self) -> Hasher<T, WithReader> {
        Hasher {
            algo: self.algo,
            phantom: PhantomData,
        }
    }
    pub fn digester(self) -> Hasher<T, WithoutReader> {
        Hasher {
            algo: self.algo,
            phantom: PhantomData,
        }
    }
}

impl<T: HashAlgorithm> Hasher<T, WithReader> {
    pub fn consumed_len(&self) -> usize {
        self.algo.bytes_len()
    }

    pub fn read(&mut self, handle: &mut dyn Read) -> String {
        let block_size = T::BLOCK_SIZE;
        let mut buffer = vec![0u8; block_size];
        while let Ok(n) = handle.read(&mut buffer) {
            self.algo.set_bytes_len(self.algo.bytes_len() + n);
            if n == 0 {
                break;
            } else if n == block_size {
                self.algo.process_block(&buffer);
            } else {
                let mut data = buffer[..n].to_vec();
                T::append_padding(&mut data, self.algo.bytes_len() * 8);
                for chunk_start in (0..data.len()).step_by(block_size) {
                    self.algo
                        .process_block(&data[chunk_start..chunk_start + block_size]);
                }
            }
        }
        self.algo.hash_string()
    }
}

impl<T: HashAlgorithm> Hasher<T, WithoutReader> {
    pub fn consumed_len(&self) -> usize {
        self.algo.data().len()
    }

    pub fn digest(&mut self, data: &[u8]) {
        self.algo.data_mut().extend_from_slice(data);
    }

    pub fn finalize(&mut self) -> String {
        let total_bits = self.algo.data().len() * 8;
        T::append_padding(self.algo.data_mut(), total_bits);
        let block_size = T::BLOCK_SIZE;
        let data = std::mem::take(self.algo.data_mut());
        for chunk_start in (0..data.len()).step_by(block_size) {
            self.algo
                .process_block(&data[chunk_start..chunk_start + block_size]);
        }
        self.algo.hash_string()
    }
}
