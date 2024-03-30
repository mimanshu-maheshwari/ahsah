# AHSAH: Hashing Algorithm implementations

Implementation of SHA-256 algorithm in rust as library.

Currently file hasher only supports string data in files. Binary data is not supported.
but library takes bytes only so can can create a binary file hasher as well.

In release you can download hashers:
```console
$ ./file_hasher.exe <filename>
$ ./string_hasher.exe "string"
$ ./stdin_hasher.exe <<< "datastring"
$ echo "data" | ./stdin_hasher.exe 
$ cat filename | ./stdin_hasher.exe
```


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
