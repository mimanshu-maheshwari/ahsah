use std::io::Cursor;

use ahsah::{HashBuilder, Sha256};

#[test]
fn legacy_builder_matches_new_api() {
    let input = b"compatibility matters";
    let expected = Sha256::digest(input).to_hex();

    let mut legacy = HashBuilder::sha256().digester();
    legacy.digest(input);
    assert_eq!(expected, legacy.finalize());
}

#[test]
fn legacy_reader_matches_new_api() {
    let input = b"reader compatibility matters";
    let expected = Sha256::digest(input).to_hex();

    let mut legacy = HashBuilder::sha256().reader();
    let mut reader = Cursor::new(input);
    assert_eq!(expected, legacy.read(&mut reader));
}
