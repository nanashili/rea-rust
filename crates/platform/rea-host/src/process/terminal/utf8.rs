//! Streaming UTF-8 decoding with Node.js `StringDecoder('utf8')` semantics
//! (`src/string_decoder.cc`), which is how node-pty hands PTY bytes to xterm
//! in the TypeScript oracle.
//!
//! Node buffers a trailing incomplete character, completes it from the next
//! chunk (abandoning it at the first non-continuation byte), and decodes each
//! piece with V8, which substitutes U+FFFD per maximal invalid subpart — the
//! same policy as `String::from_utf8_lossy`.

#[derive(Clone, Debug, Default)]
pub struct Utf8Decoder {
    incomplete: [u8; 4],
    buffered: usize,
    missing: usize,
}

impl Utf8Decoder {
    /// Decode one chunk; an incomplete trailing character carries over.
    pub fn write(&mut self, chunk: &[u8]) -> String {
        let mut data = chunk;
        let mut prepend: Option<String> = None;
        if self.missing > 0 {
            for (i, byte) in data.iter().enumerate().take(self.missing) {
                if byte & 0xC0 != 0x80 {
                    self.missing = 0;
                    self.incomplete[self.buffered..self.buffered + i].copy_from_slice(&data[..i]);
                    self.buffered += i;
                    data = &data[i..];
                    break;
                }
            }
            let found = data.len().min(self.missing);
            self.incomplete[self.buffered..self.buffered + found].copy_from_slice(&data[..found]);
            data = &data[found..];
            self.missing -= found;
            self.buffered += found;
            if self.missing == 0 {
                prepend = Some(String::from_utf8_lossy(&self.incomplete[..self.buffered]).into_owned());
                self.buffered = 0;
            }
        }
        if data.is_empty() {
            return prepend.unwrap_or_default();
        }
        if data[data.len() - 1] & 0x80 != 0 {
            let mut i = data.len() - 1;
            loop {
                self.buffered += 1;
                if data[i] & 0xC0 == 0x80 {
                    if self.buffered >= 4 || i == 0 {
                        self.buffered = 0;
                        break;
                    }
                } else {
                    self.missing = if data[i] & 0xE0 == 0xC0 {
                        2
                    } else if data[i] & 0xF0 == 0xE0 {
                        3
                    } else if data[i] & 0xF8 == 0xF0 {
                        4
                    } else {
                        self.buffered = 0;
                        break;
                    };
                    if self.buffered >= self.missing {
                        self.missing = 0;
                        self.buffered = 0;
                    }
                    self.missing -= self.buffered;
                    break;
                }
                i -= 1;
            }
        }
        let body_len = data.len() - self.buffered;
        self.incomplete[..self.buffered].copy_from_slice(&data[body_len..]);
        let body = String::from_utf8_lossy(&data[..body_len]);
        match prepend {
            Some(mut text) => {
                text.push_str(&body);
                text
            }
            None => body.into_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Utf8Decoder;

    fn decode(chunks: &[&[u8]]) -> String {
        let mut decoder = Utf8Decoder::default();
        chunks.iter().map(|chunk| decoder.write(chunk)).collect()
    }

    #[test]
    fn carries_split_characters_and_replaces_invalid_bytes_like_node() {
        assert_eq!(decode(&[b"\xc3", b"\xa9"]), "é");
        assert_eq!(decode(&[b"\xe2\x82", b"\xac!"]), "€!");
        // Interrupted sequence: the buffered prefix becomes one replacement.
        assert_eq!(decode(&[b"\xe2\x82", b"A"]), "\u{FFFD}A");
        assert_eq!(decode(&[b"a\xffb"]), "a\u{FFFD}b");
        assert_eq!(decode(&[b"\x80\x80"]), "\u{FFFD}\u{FFFD}");
    }
}
