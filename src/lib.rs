//! AHSAH is a small hashing crate with incremental digest contexts,
//! reader helpers, and compatibility shims for the older builder API.

pub mod algorithms;
mod buffer;
#[cfg(feature = "args")]
pub mod cli;
pub mod digest;
pub mod encoding;
pub mod hasher;
pub mod io;

pub use algorithms::{Md5, Sha224, Sha256, Sha384, Sha512, MD5};
#[cfg(feature = "args")]
pub use cli::{Args, HashingAlgo};
pub use digest::Digest;
pub use encoding::DigestBytes;
pub use hasher::{Generic, HashBuilder, Hasher, WithReader, WithoutReader};
pub use io::{digest_reader, update_reader};

#[deprecated(since = "2.1.0", note = "use ahsah::HashBuilder instead")]
pub mod hashes {
    pub use crate::hasher::*;
}
