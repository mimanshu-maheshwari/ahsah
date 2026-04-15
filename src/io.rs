use std::io::{self, Read};

use crate::{digest::Digest, encoding::DigestBytes};

const READER_BUFFER_SIZE: usize = 8 * 1024;

pub fn update_reader<D: Digest, R: Read + ?Sized>(
    digest: &mut D,
    reader: &mut R,
) -> io::Result<u64> {
    let mut buffer = [0u8; READER_BUFFER_SIZE];
    let mut read_total = 0u64;

    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            return Ok(read_total);
        }
        digest.update(&buffer[..read]);
        read_total += read as u64;
    }
}

pub fn digest_reader<D, R>(reader: &mut R) -> io::Result<DigestBytes>
where
    D: Digest + Default,
    R: Read + ?Sized,
{
    let mut digest = D::default();
    update_reader(&mut digest, reader)?;
    Ok(digest.finalize())
}
