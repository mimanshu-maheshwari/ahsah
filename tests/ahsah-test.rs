
#[cfg(test)]
pub mod ahsah_test {

    use sha256::hash;

    #[test]
    fn test1() {
        hash(b"Hello sha256");
    }
}
