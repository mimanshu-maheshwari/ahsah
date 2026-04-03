pub mod algo;
pub mod hasher;
pub mod traits;
pub(crate) mod utils;

// Re-exports for convenience
pub use algo::md5::MD5;
pub use algo::sha256::Sha256;
pub use algo::sha512::Sha512;
pub use hasher::{HashBuilder, Hasher};
pub use traits::HashAlgorithm;

// Re-export utils for the #[cfg(feature = "args")] types
pub use utils::*;

// Backward compatibility (deprecated)
#[deprecated(since = "2.0.0", note = "use ahsah::hasher instead")]
pub mod hashes {
    pub use crate::hasher::*;
}
