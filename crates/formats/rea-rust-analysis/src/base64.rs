//! Small standard-base64 encoder shared by lossless source-byte reports.

pub(crate) fn encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::with_capacity(bytes.len().div_ceil(3) * 4);

    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied();
        let third = chunk.get(2).copied();

        encoded.push(ALPHABET[usize::from(first >> 2)] as char);
        encoded.push(
            ALPHABET[usize::from(((first & 0b11) << 4) | (second.unwrap_or(0) >> 4))] as char,
        );
        encoded.push(match second {
            Some(second) => {
                ALPHABET[usize::from(((second & 0b1111) << 2) | (third.unwrap_or(0) >> 6))] as char
            }
            None => '=',
        });
        encoded.push(match third {
            Some(third) => ALPHABET[usize::from(third & 0b0011_1111)] as char,
            None => '=',
        });
    }

    encoded
}
