#[cfg(test)]
pub mod hash_tests {
    pub mod sha512_test {

        use ahsah::{hashes::AhsahHasher, sha512::Sha512};
        #[test]
        fn test_empty() {
            let input = b"";
            let expected = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
            let mut hasher = Sha512::new();
            hasher.digest(input);
            assert_eq!(expected, hasher.finish());
        }
        #[test]
        fn test_abc() {
            let input = b"abc";
            let expected = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
            let mut hasher = Sha512::new();
            hasher.digest(input);
            assert_eq!(expected, hasher.finish());
        }

        #[test]
        fn test_hello_world() {
            let input = b"hello world";
            let expected = "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f";
            let mut hasher = Sha512::new();
            hasher.digest(input);
            assert_eq!(expected, hasher.finish());
        }

        #[test]
        fn test_quick_brown_fox() {
            let input = b"The quick brown fox jumps over the lazy dog";
            let expected = "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6";
            let mut hasher = Sha512::new();
            hasher.digest(input);
            assert_eq!(expected, hasher.finish());
        }

        #[test]
        fn test_microsoft_crt() {
            let input = b"There is a feature of Microsoft's CRT (C runtime, it is also used for Rust programs) which automatically detects memory corruption and aborts the program to minimize further destruction and mitigating malicious exploits.";
            let expected = "fc12895e335dae4559b7327f6b05f38a9180c0b6d91a9d8e5b51f035c69b2edd6e67977ef905b253a5b60968f9619f8568c8c59a3b645074a96b8dbf162fc7cd";
            let mut hasher = Sha512::new();
            hasher.digest(input);
            assert_eq!(expected, hasher.finish());
        }

        #[test]
        fn test_long_temp() {
            let input = b"adkfja;ldkfa;ofeha;ldkfja;lghqoiehoar238ru qtyq98435y3u03841q398r75q98etn q9ewytqtorynqpyrq984rqn9 r8tuq93845nvut19384yn1v9348y 98134y519p84y519 ytq9uytqp934y8t qp4utyqp9843utn viejqwphf3g i;DHSFH FPTPQT8QU98UPQ9TUP439T698526 Y28UPAGUH OIU  i pqotuwp98tuq049tuq34p948ty qp84turehgpqiuhgqtp9rh wpiorghqipurhgqpitjq34p9hpothtq348 ytp9hgqpoij go[iqergjnvlang aghqoitj [q34i typ9q852y626810t -2480976 2-9538t4hgpqoireghqpoergh e;ogherq";
            let expected = "798924da0dc6813e8f3f60ffa90110e10f9fad224da69dfb7a5010a2ab73a890e1e126328175f7226eda9bddfed400c1c083687bfdc68e316ad78ee93d644b7d";
            let mut hasher = Sha512::new();
            hasher.digest(input);
            assert_eq!(expected, hasher.finish());
        }

        #[test]
        fn test_maheshwari() {
            let input = b"maheshwari";
            let expected = "3b1f81c11d1cefd8ea7a310b5511c831222b3caa5290501d4708cc5c280e4dfcc15b7808697c4d760054e21a96557eaaec38947627ced05f33afa173b31a7afa";
            let mut hasher = Sha512::new();
            hasher.digest(input);
            assert_eq!(expected, hasher.finish());
        }
    }

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
//     use ahsah::sha512::Sha512;
//
//     #[test]
//     fn padding_test_1(){
//         let mut msg:Vec<u8> = vec![61, 62, 63];
//         let mut expected: Vec<u8> = vec![61, 62, 63, 0x80];
//         let mut zero_padding: Vec<u8> = vec![0; 123];
//         expected.append(&mut zero_padding);
//         expected.push(24);
//         Sha512::add_padding(&mut msg);
//         assert_eq!(expected.len(), msg.len());
//         assert_eq!(expected, msg);
//     }
// }
