# AHSAH: Hashing Algorithm implementations

Implementation of SHA-256 and SHA-512 algorithm in rust as library.

Currently `file_hasher` only supports string data in files. Binary data is not supported.
But library takes bytes only so, you can create a binary file hasher as well.

In release you can download hashers for sha256:
```console
$ ./file_hasher.exe <filename>
$ ./string_hasher.exe "string"
$ ./stdin_hasher.exe <<< "datastring"
$ echo "data" | ./stdin_hasher.exe 
$ cat filename | ./stdin_hasher.exe
```

## Example: 
* SHA 256
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
      hasher.digest(&message.as_bytes());
      println!("{}", hasher.finish());
  }
  ```
	Output: 
	```console
	➜ ahsah ⚡
	▶ cargo r -q -- "abc"
	ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
	```
* SHA 512
  ```rust
  use ahsah::{hashes::AhsahHasher, sha512::Sha512};
  use std::env::args;
  
  fn main() {
      let args = args();
      let message: String = match args.skip(1).next() {
          Some(val) => val,
          None => String::from("abc"),
      };
      let mut hasher = Sha512::new();
      hasher.digest(&message.as_bytes());
      println!("{}", hasher.finish());
  }
  ```
	Output: 
	```console
	➜ ahsah ⚡
	▶ cargo r -q -- "abc"
	ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f
	```


In future will implement more algorithms

## Extra Unrelated Links
* https://github.com/marketplace/actions/build-and-upload-rust-binary-to-github-releases
* https://github.com/marketplace/actions/rust-release-binary
