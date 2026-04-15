use ahsah::Sha512;

#[test]
fn sha512_known_vectors() {
    let vectors = [
        ("", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"),
        ("abc", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
        (
            "The quick brown fox jumps over the lazy dog",
            "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6",
        ),
    ];

    for (input, expected) in vectors {
        assert_eq!(expected, Sha512::digest(input.as_bytes()).to_hex());
    }
}
