use ahsah::Md5;

#[test]
fn md5_known_vectors() {
    let vectors = [
        ("", "d41d8cd98f00b204e9800998ecf8427e"),
        ("a", "0cc175b9c0f1b6a831c399e269772661"),
        ("abc", "900150983cd24fb0d6963f7d28e17f72"),
        ("message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
        (
            "The quick brown fox jumps over the lazy dog",
            "9e107d9d372bb6826bd81d3542a419d6",
        ),
    ];

    for (input, expected) in vectors {
        assert_eq!(expected, Md5::digest(input.as_bytes()).to_hex());
    }
}
