![Crates.io Total Downloads](https://img.shields.io/crates/d/ahsah)
![Crates.io Downloads (recent)](https://img.shields.io/crates/dr/ahsah)

# AHSAH: Hashing Algorithm implementations

- A collection of hashing algorithms which support buffered hashing through Read trait.
- In future will implement more algorithms, but currently we only have Sha256, Sha512 and MD5.

## Example

> Using feature flag `args` following things can be done using clap.
> `ahsah::utils::Args` provides flags like `--algo`, `--time` and `--file`

### Reader example

```rust
use ahsah::utils::{Args, HashingAlgo::*};
use ahsah::hashes::HashBuilder;
use clap::Parser;
use std::{
    fs::File,
    io::{stdin, BufReader, Read},
    path::Path,
    time::Instant,
};

fn main() {
    let args = Args::parse();
    let now = Instant::now();

    let mut handle: Box<dyn Read> = match args.file {
        Some(path) => {
            let path = Path::new(&path);
            Box::new(BufReader::new(File::open(path).unwrap()))
        }
        None => Box::new(stdin().lock()),
    };

    let hash = match args.algo {
        Sha512 => HashBuilder::sha512().reader().read(&mut handle),
        Sha256 => HashBuilder::sha256().reader().read(&mut handle),
    };

    let elapsed = now.elapsed();
    if args.time {
        println!(
            "{:?} took ({} ns | {} ms | {} s)",
            &args.algo,
            elapsed.as_nanos(),
            (elapsed.as_nanos() as f64 / 10e5),
            (elapsed.as_nanos() as f64 / 10e8),
        );
    }
    println!("{}", hash);
}
```

### SHA 256 digester

```rust
use ahsah::hashes::HashBuilder;
fn main() {
  let message = b"abc";
  let mut hasher = HashBuilder::sha256().digester();
    hasher.digest(&message);
    println!("{}", hasher.finalize());
}
```

    Output:
    ```console
    ➜ ahsah ⚡
    ▶ cargo r
    ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    ```

### SHA 512 digester

```rust
use ahsah::hashes::HashBuilder;
fn main() {
 let message = b"abc";
 let mut hasher = HashBuilder::sha512().digester();
  hasher.digest(&message);
  println!("{}", hasher.finalize());
}
```

Output:

```console
➜ ahsah ⚡
▶ cargo r -q
ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f
```

### `reader-hasher.exe` example

```console
➜ tests ⚡                                                                                                   22:58:32
▶ du -b data.zip
3326642876      data.zip
➜ tests ⚡                                                                                                   22:58:34
▶ ./reader-hasher.exe -a sha256 -f data.zip
32ce88a708c5eef77796194c408a653094bd28f9114eb521825c66fb6df8d12f

➜ tests ⚡                                                                                                   22:58:53
▶ ./reader-hasher.exe -a sha512 -f data.zip
5dfe1446c13d7b46e59bbc78b8b72c9badc13ba6172647c451ccdf47dd2ccd15d156aa221cc8c2feb9bbb03bc6e8a7c5212e60d25d3ebbd4876ae8e96b1b7bce
```

# References

- [SHA-2](<https://en.w>
  kikipedia.org/wiki/SHA-2)
- [MD5](https://en.wikipedia.org/wiki/MD5)
- [rfc1321](https://www.ietf.org/rfc/rfc1321.txt)
