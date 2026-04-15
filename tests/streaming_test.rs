use std::io::Cursor;

use ahsah::{digest_reader, update_reader, Digest, Md5, Sha224, Sha256, Sha384, Sha512};

fn assert_streaming_matches<D>(input: &[u8])
where
    D: Digest + Default,
{
    let one_shot = D::digest(input).to_hex();

    let mut chunked = D::default();
    for chunk in input.chunks(3) {
        chunked.update(chunk);
    }
    assert_eq!(one_shot, chunked.finalize_hex());

    let mut reader_digest = D::default();
    let mut reader = Cursor::new(input);
    update_reader(&mut reader_digest, &mut reader).unwrap();
    assert_eq!(one_shot, reader_digest.finalize_hex());

    let mut reader = Cursor::new(input);
    assert_eq!(
        one_shot,
        digest_reader::<D, _>(&mut reader).unwrap().to_hex()
    );
}

#[test]
fn streaming_matches_for_supported_algorithms() {
    let input = b"chunked input that spans more than one block and verifies reader helpers";
    assert_streaming_matches::<Md5>(input);
    assert_streaming_matches::<Sha224>(input);
    assert_streaming_matches::<Sha256>(input);
    assert_streaming_matches::<Sha384>(input);
    assert_streaming_matches::<Sha512>(input);
}
