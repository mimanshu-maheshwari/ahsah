use std::marker::PhantomData;

use crate::{sha256::Sha256, sha512::Sha512};
// #[cfg(feature = "args")]
// #[derive(ValueEnum)]

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
}

pub struct Hasher<T, B> {
    pub(crate) algo: T,
    pub(crate) phantom: PhantomData<B>,
}

pub struct WithReader;
pub struct WithoutReader;
pub struct Generic;

// pub trait Hasher {
//     fn digest(&mut self, data: &[u8]);
//     fn finish(&mut self) -> String;
//     fn new() -> Self
//     where
//         Self: Sized;
//     fn consumed_len(&self) -> usize;
// }
//
// pub trait BufferedHasher {
//     fn new() -> Self
//     where
//         Self: Sized;
//     fn hash_bufferd(&mut self, handle: &mut dyn Read) -> String;
//
//     fn consumed_len(&self) -> usize;
// }
