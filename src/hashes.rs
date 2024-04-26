use std::marker::PhantomData;

use crate::{md5::MD5, sha256::Sha256, sha512::Sha512};
// #[cfg(feature = "args")]
// #[derive(ValueEnum)]

pub struct WithReader;
pub struct WithoutReader;
pub struct Generic;

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

pub struct Hasher<T, B> {
    pub(crate) algo: T,
    pub(crate) phantom: PhantomData<B>,
}
