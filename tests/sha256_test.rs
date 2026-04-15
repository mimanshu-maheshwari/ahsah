use ahsah::Sha256;

#[test]
fn sha256_known_vectors() {
    let vectors = [
        (
            "",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        (
            "abc",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
        (
            "The quick brown fox jumps over the lazy dog",
            "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
        ),
        (
            "hello world",
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
        ),
    ];

    for (input, expected) in vectors {
        assert_eq!(expected, Sha256::digest(input.as_bytes()).to_hex());
    }
}
