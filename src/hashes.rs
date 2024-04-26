use std::marker::PhantomData;

use crate::{sha256::Sha256, sha512::Sha512};
// #[cfg(feature = "args")]
// #[derive(ValueEnum)]

#[derive(Debug, Clone)]
pub enum HashingAlgo {
    Sha512,
    Sha256,
    //MD5, 
    //Undefined,
}

pub struct HashBuilder;

impl HashBuilder {
    pub fn new<T>(algo: HashingAlgo) -> Hasher<T, Generic> {
        match algo {
            HashingAlgo::Sha512 => Hasher::<Sha512, Generic>{algo: Sha512::new(), phantom: PhantomData},
            HashingAlgo::Sha256 => Hasher::<Sha256, Generic>{algo: Sha256::new(), phantom: PhantomData},
        }
    }
}

pub struct Hasher<T, B> {
    pub(crate) algo: T, 
    pub(crate) phantom: PhantomData<B>
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
