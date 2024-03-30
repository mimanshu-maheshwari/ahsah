#[cfg(test)]
pub mod hash_tests {

    use sha256::hash;
    #[test]
    fn test_empty() {
        let input = b"";
        let expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(expected, hash(input));
    }
    #[test]
    fn test_abc(){
        let input = b"abc";
        let expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert_eq!(expected, hash(input));
     }

    #[test]
    fn test_hello_world() {
        let input = b"hello world";
        let expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        assert_eq!(expected, hash(input));
    }

    #[test]
    fn test_quick_brown_fox() {
        let input = b"The quick brown fox jumps over the lazy dog";
        let expected = "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592";
        assert_eq!(expected, hash(input));
    }

    #[test]
    fn test_microsoft_crt() {
        let input = b"There is a feature of Microsoft's CRT (C runtime, it is also used for Rust programs) which automatically detects memory corruption and aborts the program to minimize further destruction and mitigating malicious exploits.";
        let expected = "348fd4546abaeaadc9e556b3b7d491724269be351012997f0316e3be43f2f6f5";
        assert_eq!(expected, hash(input));
    }


}
pub mod logical_function_tests {
    use sha256::add_padding; 

    #[test]
    fn padding_test_1(){
        let mut msg:Vec<u8> = vec![61, 62, 63]; 
        let mut expected: Vec<u8> = vec![61, 62, 63, 0x80];
        let mut zero_padding: Vec<u8> = vec![0; 59]; 
        expected.append(&mut zero_padding);
        expected.push(24);
        add_padding(&mut msg);
        assert_eq!(expected.len(), msg.len());
        assert_eq!(expected, msg);
    }

}
