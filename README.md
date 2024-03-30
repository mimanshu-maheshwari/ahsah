# AHSAH: Hashing Algorithm implementations

Implementation of SHA-256 algorithm in rust as library.

use sha256 module and import the hash function.
hash function takes slice of bytes. and returns hash value as String

## Usage: 
```rust
use ahsah::sha256::hash;
use std::env::args;

fn main() {
    let args = args();
    let message: String = match args.skip(1).next() {
        Some(val) => val,
        None => String::from("abc"),
    };
    println!("{}", hash(message.as_bytes()));
}
```
Output: 
```console
➜ ahsah ⚡
▶ cargo r -q -- "abc"
ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
```

In future will implement more algorithms
