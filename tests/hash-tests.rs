
#[cfg(test)]
pub mod hash_tests {

    use sha256::hash;
    #[test]
    fn test_empty() {
        let input = b"";
        let expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        if let Some(actual) = hash(input) {
            let actual: &str = &actual;
            assert_eq!(expected, actual);
        }
    }
     #[test]
    fn test_2() {
        let input = b"The quick brown fox jumps over the lazy dog";
        let expected = "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592";
        if let Some(actual) = hash(input) {
            let actual: &str = &actual;
            assert_eq!(expected, actual);
        }
    }
     #[test]
    fn test_small_string() {
        let input = b"hello world";
        let expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        if let Some(actual) = hash(input) {
            let actual: &str = &actual;
            assert_eq!(expected, actual);
        }
    }
    #[test]
    fn test_medium_string() {
        let input = b"There is a feature of Microsoft's CRT (C runtime, it is also used for Rust programs) which automatically detects memory corruption and aborts the program to minimize further destruction and mitigating malicious exploits.";
        let expected = "348fd4546abaeaadc9e556b3b7d491724269be351012997f0316e3be43f2f6f5";
        if let Some(actual) = hash(input) {
            let actual: &str = &actual;
            assert_eq!(expected, actual);
        }
    }
}
