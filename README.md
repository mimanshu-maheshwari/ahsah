![Crates.io Total Downloads](https://img.shields.io/crates/d/ahsah)
![Crates.io Downloads (recent)](https://img.shields.io/crates/dr/ahsah)

# AHSAH

`ahsah` is a small Rust hashing crate built around incremental digest contexts.

Supported algorithms:

- `Md5`
- `Sha224`
- `Sha256`
- `Sha384`
- `Sha512`

The crate includes:

- typed digest contexts with `new`, `update`, `finalize`, `finalize_hex`, and `digest`
- raw digest bytes via `DigestBytes`
- reader helpers for hashing `Read` streams
- compatibility shims for the legacy `HashBuilder` API
- optional SIMD-assisted block decoding through the `simd` feature

## Installation

```toml
[dependencies]
ahsah = "2.0.0"
```

Optional features:

- `args`: enables `clap`-based example argument parsing helpers
- `simd`: enables optional SIMD-assisted block decoding on supported `x86`/`x86_64` CPUs, with scalar fallback everywhere else

## Quick Start

### One-shot hashing

```rust
use ahsah::Sha256;

fn main() {
    let digest = Sha256::digest(b"abc");
    println!("{}", digest);
}
```

### Incremental hashing

```rust
use ahsah::{Digest, Sha512};

fn main() {
    let mut digest = Sha512::new();
    digest.update(b"hello ");
    digest.update(b"world");

    let hex = digest.finalize_hex();
    println!("{hex}");
}
```

### Hashing any `Read`

```rust
use ahsah::{digest_reader, Sha384};
use std::io::Cursor;

fn main() -> std::io::Result<()> {
    let mut reader = Cursor::new(b"streamed input");
    let digest = digest_reader::<Sha384, _>(&mut reader)?;
    println!("{}", digest);
    Ok(())
}
```

### Raw digest bytes

```rust
use ahsah::Sha224;

fn main() {
    let digest = Sha224::digest(b"abc");
    assert_eq!(28, digest.len());
    assert_eq!(
        "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
        digest.to_hex()
    );
}
```

## Legacy Compatibility

The older builder API is still available during the transition:

```rust
use ahsah::HashBuilder;

fn main() {
    let mut hasher = HashBuilder::sha256().digester();
    hasher.digest(b"abc");
    println!("{}", hasher.finalize());
}
```

The deprecated `ahsah::hashes::HashBuilder` path also continues to work.

## Examples

Run the examples with:

```console
cargo run --example string-hasher -- "hello"
cargo run --example stdin-hasher
cargo run --example reader-hasher --features args -- --algo sha256 --file ./res/test.txt
cargo run --example file-hasher --features args -- --algo sha512 --file ./res/test.txt
```

Algorithms accepted by the `args` feature examples:

- `md5`
- `sha224`
- `sha256`
- `sha384`
- `sha512`

## Notes on SIMD

The `simd` feature is optional and conservative:

- scalar implementations remain the canonical fallback
- current SIMD work accelerates block word decoding on supported `x86`/`x86_64` CPUs
- digest outputs are covered by parity tests against the scalar path

## Testing

```console
cargo test --tests --lib
cargo test --tests --lib --features simd
cargo test --examples --features args
```

## Benchmarks

Criterion benchmarks live in [benches/digest_benchmarks.rs](D:/Projects/rust/ahsah/benches/digest_benchmarks.rs).

They currently cover:

- `Md5`, `Sha224`, `Sha256`, `Sha384`, and `Sha512`
- one-shot hashing and incremental chunked hashing
- input sizes `0`, `64`, `1024`, and `16 KiB`

Run them with:

```console
cargo bench --bench digest_benchmarks
cargo bench --bench digest_benchmarks --features simd
```

## References

- [SHA-2](https://en.wikipedia.org/wiki/SHA-2)
- [MD5](https://en.wikipedia.org/wiki/MD5)
- [RFC 1321](https://www.rfc-editor.org/rfc/rfc1321)
