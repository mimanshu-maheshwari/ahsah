use ahsah::Sha224;

#[test]
fn sha224_known_vectors() {
    let vectors = [
        (
            "",
            "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
        ),
        (
            "abc",
            "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
        ),
        (
            "The quick brown fox jumps over the lazy dog",
            "730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525",
        ),
    ];

    for (input, expected) in vectors {
        assert_eq!(expected, Sha224::digest(input.as_bytes()).to_hex());
    }
}
