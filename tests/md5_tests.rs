use ahsah::hashes::HashBuilder;

#[test]
fn test_empty() {
    let input = b"";
    let expected = "d41d8cd98f00b204e9800998ecf8427e";
    let mut hasher = HashBuilder::md5().digester();
    hasher.digest(input);
    let actual = hasher.finalize();
    assert_eq!(expected, actual);
}

#[test]
fn test_quick_brown_fox() {
    let input = b"The quick brown fox jumps over the lazy dog";
    let expected = "9e107d9d372bb6826bd81d3542a419d6";
    let mut hasher = HashBuilder::md5().digester();
    hasher.digest(input);
    let actual = hasher.finalize();
    assert_eq!(expected, actual);
}


#[test]
fn test_quick_brown_fox_dot() {
    let input = b"The quick brown fox jumps over the lazy dog.";
    let expected = "e4d909c290d0fb1ca068ffaddf22cbd0";
    let mut hasher = HashBuilder::md5().digester();
    hasher.digest(input);
    let actual = hasher.finalize();
    assert_eq!(expected, actual);
}

