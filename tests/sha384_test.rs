use ahsah::Sha384;

#[test]
fn sha384_known_vectors() {
    let vectors = [
        ("", "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"),
        ("abc", "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"),
        (
            "The quick brown fox jumps over the lazy dog",
            "ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1",
        ),
    ];

    for (input, expected) in vectors {
        assert_eq!(expected, Sha384::digest(input.as_bytes()).to_hex());
    }
}
