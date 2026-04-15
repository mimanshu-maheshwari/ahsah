use std::{io::Read, marker::PhantomData};

use crate::{digest::Digest, io::update_reader, Md5, Sha224, Sha256, Sha384, Sha512};

pub struct WithReader;
pub struct WithoutReader;
pub struct Generic;

pub struct Hasher<T, B> {
    pub(crate) algo: T,
    pub(crate) phantom: PhantomData<B>,
}

pub struct HashBuilder;

impl HashBuilder {
    pub fn sha224() -> Hasher<Sha224, Generic> {
        Hasher::new(Sha224::new())
    }

    pub fn sha256() -> Hasher<Sha256, Generic> {
        Hasher::new(Sha256::new())
    }

    pub fn sha384() -> Hasher<Sha384, Generic> {
        Hasher::new(Sha384::new())
    }

    pub fn sha512() -> Hasher<Sha512, Generic> {
        Hasher::new(Sha512::new())
    }

    pub fn md5() -> Hasher<Md5, Generic> {
        Hasher::new(Md5::new())
    }
}

impl<T, B> Hasher<T, B> {
    fn new(algo: T) -> Self {
        Self {
            algo,
            phantom: PhantomData,
        }
    }
}

impl<T: Digest> Hasher<T, Generic> {
    pub fn reader(self) -> Hasher<T, WithReader> {
        Hasher::new(self.algo)
    }

    pub fn digester(self) -> Hasher<T, WithoutReader> {
        Hasher::new(self.algo)
    }
}

impl<T: Digest> Hasher<T, WithReader> {
    pub fn consumed_len(&self) -> usize {
        self.algo.input_size() as usize
    }

    pub fn read<R: Read>(&mut self, handle: &mut R) -> String {
        update_reader(&mut self.algo, handle).expect("failed to read from input");
        self.algo.clone().finalize_hex()
    }
}

impl<T: Digest> Hasher<T, WithoutReader> {
    pub fn consumed_len(&self) -> usize {
        self.algo.input_size() as usize
    }

    pub fn digest(&mut self, data: &[u8]) {
        self.algo.update(data);
    }

    pub fn finalize(&mut self) -> String {
        self.algo.clone().finalize_hex()
    }
}
