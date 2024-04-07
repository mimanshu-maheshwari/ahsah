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
* Buffered example: 
	```rust
	use ahsah::{
			hashes::AhsahBufferedHasher,
			sha256::Sha256,
			sha512::Sha512,
			utils::{Args, HashingAlgo::*},
	};
	use clap::Parser;
	use std::{
			fs::File,
			io::{stdin, BufReader, Read},
			path::Path,
	};

	fn main() {
			let args = Args::parse();

			let mut handle: Box<dyn Read> = match args.file {
					Some(path) => {
							let path = Path::new(&path);
							Box::new(BufReader::new(File::open(path).unwrap()))
					}
					None => Box::new(stdin().lock()),
			};

			let mut hasher: Box<dyn AhsahBufferedHasher> = match args.algo {
					Sha512 => Box::new(Sha512::new()),
					Sha256 => Box::new(Sha256::new()),
			};

			println!("{}", hasher.hash_bufferd(&mut handle));
	}
	```

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
### `ahsah.exe` usage:

```console
➜ tests ⚡                                                                                                   22:58:32
▶ du -b data.zip
3326642876      data.zip
➜ tests ⚡                                                                                                   22:58:34
▶ time ./ahsah.exe -a sha256 -f data.zip
32ce88a708c5eef77796194c408a653094bd28f9114eb521825c66fb6df8d12f

real    0m15.968s
user    0m0.000s
sys     0m0.000s

➜ tests ⚡                                                                                                   22:58:53
▶ time ./ahsah.exe -a sha512 -f data.zip
5dfe1446c13d7b46e59bbc78b8b72c9badc13ba6172647c451ccdf47dd2ccd15d156aa221cc8c2feb9bbb03bc6e8a7c5212e60d25d3ebbd4876ae8e96b1b7bce

real    0m10.830s
user    0m0.000s
sys     0m0.000s
```

In future will implement more algorithms

## Release actions github
* https://github.com/marketplace/actions/build-and-upload-rust-binary-to-github-releases
* https://github.com/marketplace/actions/rust-release-binary
* https://github.com/marketplace/actions/upload-files-to-a-github-release
