#[cfg(test)]
pub mod hash_tests {

    pub mod sha256_test {

        use ahsah::{hashes::AhsahHasher, sha256::Sha256};
        #[test]
        fn test_empty() {
            let input = b"";
            let expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
            let mut hasher = Sha256::new();
            hasher.digest(input);
            assert_eq!(expected, hasher.finish());
        }
        #[test]
        fn test_abc() {
            let input = b"abc";
            let expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
            let mut hasher = Sha256::new();
            hasher.digest(input);
            assert_eq!(expected, hasher.finish());
        }

        #[test]
        fn test_hello_world() {
            let input = b"hello world";
            let expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
            let mut hasher = Sha256::new();
            hasher.digest(input);
            assert_eq!(expected, hasher.finish());
        }

        #[test]
        fn test_quick_brown_fox() {
            let input = b"The quick brown fox jumps over the lazy dog";
            let expected = "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592";
            let mut hasher = Sha256::new();
            hasher.digest(input);
            assert_eq!(expected, hasher.finish());
        }

        #[test]
        fn test_microsoft_crt() {
            let input = b"There is a feature of Microsoft's CRT (C runtime, it is also used for Rust programs) which automatically detects memory corruption and aborts the program to minimize further destruction and mitigating malicious exploits.";
            let expected = "348fd4546abaeaadc9e556b3b7d491724269be351012997f0316e3be43f2f6f5";
            let mut hasher = Sha256::new();
            hasher.digest(input);
            assert_eq!(expected, hasher.finish());
        }

        #[test]
        fn test_long_temp() {
            let input = b"adkfja;ldkfa;ofeha;ldkfja;lghqoiehoar238ru qtyq98435y3u03841q398r75q98etn q9ewytqtorynqpyrq984rqn9 r8tuq93845nvut19384yn1v9348y 98134y519p84y519 ytq9uytqp934y8t qp4utyqp9843utn viejqwphf3g i;DHSFH FPTPQT8QU98UPQ9TUP439T698526 Y28UPAGUH OIU  i pqotuwp98tuq049tuq34p948ty qp84turehgpqiuhgqtp9rh wpiorghqipurhgqpitjq34p9hpothtq348 ytp9hgqpoij go[iqergjnvlang aghqoitj [q34i typ9q852y626810t -2480976 2-9538t4hgpqoireghqpoergh e;ogherq";
            let expected = "fadb398e383fdb66197a2ed9bb9ff90aeb8c902366718124a8fe17fd678e3c46";
            let mut hasher = Sha256::new();
            hasher.digest(input);
            assert_eq!(expected, hasher.finish());
        }

        #[test]
        fn test_maheshwari() {
            let input = b"maheshwari";
            let expected = "0bd28feb624417cb316a1c2cb73e3aaabceed9c54fafaafe6fed323987a160f5";
            let mut hasher = Sha256::new();
            hasher.digest(input);
            assert_eq!(expected, hasher.finish());
        }
    }
}
// pub mod logical_function_tests {
//     use sha256::add_padding;
//
//     #[test]
//     fn padding_test_1(){
//         let mut msg:Vec<u8> = vec![61, 62, 63];
//         let mut expected: Vec<u8> = vec![61, 62, 63, 0x80];
//         let mut zero_padding: Vec<u8> = vec![0; 59];
//         expected.append(&mut zero_padding);
//         expected.push(24);
//         add_padding(&mut msg);
//         assert_eq!(expected.len(), msg.len());
//         assert_eq!(expected, msg);
//     }
//
// }
