# AHSAH: Hashing Algorithm implementations

Implementation of SHA-256 algorithm in rust as library.


## Example: 
```rust
use ahsah::{hashes::AhsahHasher, sha256::Sha256};
use std::env::args;

fn main() {
    let args = args();
    let message: String = match args.skip(1).next() {
        Some(val) => val,
        None => String::from("abc"),
    };
    let mut hasher = Sha256::new();
    hasher.digest(message.as_bytes());
    println!("{}", hasher.finish());
}
```
Output: 
```console
➜ ahsah ⚡
▶ cargo r -q -- "abc"
ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
```

In future will implement more algorithms

## Refs
* https://github.com/marketplace/actions/build-and-upload-rust-binary-to-github-releases
* https://github.com/marketplace/actions/rust-release-binary
