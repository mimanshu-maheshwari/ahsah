use ahsah::hashes::HashBuilder;

// MD5 test suite:
// MD5 ("") = d41d8cd98f00b204e9800998ecf8427e
// MD5 ("a") = 0cc175b9c0f1b6a831c399e269772661
// MD5 ("abc") = 900150983cd24fb0d6963f7d28e17f72
// MD5 ("message digest") = f96b697d7cb7938d525a2f31aaf161d0
// MD5 ("abcdefghijklmnopqrstuvwxyz") = c3fcd3d76192e4007dfb496cca67e13b
// MD5 ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") = d174ab98d277d9f5a5611c2c9f419d9f
// MD5 ("12345678901234567890123456789012345678901234567890123456789012345678901234567890") = 57edf4a22be3c955ac49da2e2107b67a

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
fn test_a() {
    let input = b"a";
    let expected = "0cc175b9c0f1b6a831c399e269772661";
    let mut hasher = HashBuilder::md5().digester();
    hasher.digest(input);
    let actual = hasher.finalize();
    assert_eq!(expected, actual);
}
#[test]
fn test_abc() {
    let input = b"abc";
    let expected = "900150983cd24fb0d6963f7d28e17f72";
    let mut hasher = HashBuilder::md5().digester();
    hasher.digest(input);
    let actual = hasher.finalize();
    assert_eq!(expected, actual);
}
#[test]
fn test_message_digest() {
    let input = b"message digest";
    let expected = "f96b697d7cb7938d525a2f31aaf161d0";
    let mut hasher = HashBuilder::md5().digester();
    hasher.digest(input);
    let actual = hasher.finalize();
    assert_eq!(expected, actual);
}
#[test]
fn test_abcdefghijklmnopqrstuvwxyz() {
    let input = b"abcdefghijklmnopqrstuvwxyz";
    let expected = "c3fcd3d76192e4007dfb496cca67e13b";
    let mut hasher = HashBuilder::md5().digester();
    hasher.digest(input);
    let actual = hasher.finalize();
    assert_eq!(expected, actual);
}

#[test]
fn test_alpha_numeric() {
    let input = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let expected = "d174ab98d277d9f5a5611c2c9f419d9f";
    let mut hasher = HashBuilder::md5().digester();
    hasher.digest(input);
    let actual = hasher.finalize();
    assert_eq!(expected, actual);
}

#[test]
fn test_rand_num() {
    let input = b"12345678901234567890123456789012345678901234567890123456789012345678901234567890";
    let expected = "57edf4a22be3c955ac49da2e2107b67a";
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
