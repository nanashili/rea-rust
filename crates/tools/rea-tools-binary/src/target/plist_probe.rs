//! Artifact-format signatures and the bounded, incremental XML plist prolog
//! probe.
//!
//! Ports `src/domain/apple/appleArchiveFormat.ts`
//! (`hasBinaryPlistSignature`, `createXmlPlistSignatureProbe`,
//! `MAX_XML_PLIST_PROBE_BYTES`) and `src/domain/zipPackageFormat.ts`
//! (`hasZipSignature`, `isZipPackageFormat`, `zipPackageFormatForPath`).

/// TS `MAX_XML_PLIST_PROBE_BYTES`.
pub(crate) const MAX_XML_PLIST_PROBE_BYTES: usize = 1024 * 1024;

const BINARY_PLIST_MAGIC: &[u8] = &[0x62, 0x70, 0x6c, 0x69, 0x73, 0x74, 0x30, 0x30];

/// TS `hasBinaryPlistSignature(bytes)`.
pub(crate) fn has_binary_plist_signature(bytes: &[u8]) -> bool {
    BINARY_PLIST_MAGIC
        .iter()
        .enumerate()
        .all(|(index, byte)| bytes.get(index) == Some(byte))
}

/// TS `hasZipSignature(bytes)`.
pub(crate) fn has_zip_signature(bytes: &[u8]) -> bool {
    bytes.len() >= 4
        && bytes[0] == 0x50
        && bytes[1] == 0x4b
        && ((bytes[2] == 0x03 && bytes[3] == 0x04)
            || (bytes[2] == 0x05 && bytes[3] == 0x06)
            || (bytes[2] == 0x07 && bytes[3] == 0x08))
}

const ZIP_PACKAGE_FORMATS: &[&str] = &[
    "zip", "ipa", "apk", "msix", "appx", "hap", "hsp", "app-pack",
];

/// TS `isZipPackageFormat(format)`.
pub(crate) fn is_zip_package_format(format: &str) -> bool {
    ZIP_PACKAGE_FORMATS.contains(&format)
}

/// TS `zipPackageFormatForPath(path)` (lower-cased suffix dispatch).
pub(crate) fn zip_package_format_for_path(lower: &str) -> Option<&'static str> {
    if lower.ends_with(".zip") {
        Some("zip")
    } else if lower.ends_with(".ipa") {
        Some("ipa")
    } else if lower.ends_with(".apk") {
        Some("apk")
    } else if lower.ends_with(".msix") || lower.ends_with(".msixbundle") {
        Some("msix")
    } else if lower.ends_with(".appx") || lower.ends_with(".appxbundle") {
        Some("appx")
    } else if lower.ends_with(".hap") {
        Some("hap")
    } else if lower.ends_with(".hsp") {
        Some("hsp")
    } else {
        None
    }
}

/// TS `XmlPlistProbeState`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum XmlPlistProbeState {
    Pending,
    Matched,
    Rejected,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Encoding {
    Utf8,
    Utf16Le,
    Utf16Be,
}

/// Incremental, bounded XML signature scanner (TS
/// `createXmlPlistSignatureProbe`). Consumed prolog text is discarded.
pub(crate) struct XmlPlistSignatureProbe {
    state: XmlPlistProbeState,
    encoding: Option<Encoding>,
    utf16: bool,
    bom_bytes: usize,
    fed_bytes: usize,
    decoded_bytes: usize,
    preamble: Vec<u8>,
    preview: StreamDecoder,
    validator: StreamDecoder,
    scanner: PrologScanner,
}

impl XmlPlistSignatureProbe {
    pub fn new() -> Self {
        Self {
            state: XmlPlistProbeState::Pending,
            encoding: None,
            utf16: false,
            bom_bytes: 0,
            fed_bytes: 0,
            decoded_bytes: 0,
            preamble: Vec::new(),
            preview: StreamDecoder::new(),
            validator: StreamDecoder::new(),
            scanner: PrologScanner::new(),
        }
    }

    pub fn state(&self) -> XmlPlistProbeState {
        self.state
    }

    fn encoded_length(&self, text: &str) -> usize {
        if self.utf16 {
            // JS `text.length * 2`: text.length counts UTF-16 code units.
            text.encode_utf16().count() * 2
        } else {
            text.len()
        }
    }

    /// TS `write(bytes)`; returns the current state.
    pub fn write(&mut self, bytes: &[u8]) -> XmlPlistProbeState {
        if self.state != XmlPlistProbeState::Pending || bytes.is_empty() {
            return self.state;
        }
        // selected = bytes.subarray(0, MAX - fedBytes - preamble.length)
        let budget = MAX_XML_PLIST_PROBE_BYTES
            .saturating_sub(self.fed_bytes)
            .saturating_sub(self.preamble.len());
        let mut selected: Vec<u8> = bytes[..std::cmp::min(bytes.len(), budget)].to_vec();

        if self.encoding.is_none() {
            if !self.preamble.is_empty() || selected.len() < 4 {
                let mut joined = Vec::with_capacity(self.preamble.len() + selected.len());
                joined.extend_from_slice(&self.preamble);
                joined.extend_from_slice(&selected);
                selected = joined;
                if selected.len() < 4 {
                    self.preamble = selected;
                    return self.state;
                }
                self.preamble = Vec::new();
            }
            let little = selected[0] == 0xff && selected[1] == 0xfe;
            let big = selected[0] == 0xfe && selected[1] == 0xff;
            self.utf16 = little || big;
            self.bom_bytes = if self.utf16 {
                2
            } else if selected[0] == 0xef && selected[1] == 0xbb && selected[2] == 0xbf {
                3
            } else {
                0
            };
            let encoding = if little {
                Encoding::Utf16Le
            } else if big {
                Encoding::Utf16Be
            } else {
                Encoding::Utf8
            };
            self.encoding = Some(encoding);
            self.preview = StreamDecoder::with_encoding(encoding);
            self.validator = StreamDecoder::with_encoding(encoding);
        }

        // preview.decode(selected, { stream: true }) — lossy, never fails.
        let text = self.preview.decode_stream(&selected);
        let result = self.scanner.scan(&text);

        // through: bytes validated so far.
        let through = if result.state == XmlPlistProbeState::Matched {
            let consumed_text = slice_chars(&text, result.consumed);
            (self.bom_bytes + self.decoded_bytes + self.encoded_length(&consumed_text))
                .saturating_sub(self.fed_bytes)
        } else {
            selected.len()
        };
        let through = std::cmp::min(through, selected.len());

        // validator.decode(selected.subarray(0, through), { stream: true })
        match self.validator.decode_stream_fatal(&selected[..through]) {
            Ok(()) => self.state = result.state,
            Err(()) => self.state = XmlPlistProbeState::Rejected,
        }

        self.decoded_bytes += self.encoded_length(&text);
        self.fed_bytes += selected.len();
        if self.fed_bytes == MAX_XML_PLIST_PROBE_BYTES && self.state == XmlPlistProbeState::Pending
        {
            self.state = XmlPlistProbeState::Rejected;
        }
        self.state
    }
}

/// Slice the first `count` UTF-16 code units of a string as JS `text.slice`
/// does, returning that prefix re-encoded as a Rust `String`.
fn slice_chars(text: &str, count: usize) -> String {
    let units: Vec<u16> = text.encode_utf16().take(count).collect();
    String::from_utf16_lossy(&units)
}

/// A minimal streaming text decoder with a pending-bytes buffer, mirroring the
/// relevant behavior of Node `TextDecoder` for the three encodings used here.
struct StreamDecoder {
    encoding: Encoding,
    bom_stripped: bool,
    pending: Vec<u8>,
}

impl StreamDecoder {
    fn new() -> Self {
        Self {
            encoding: Encoding::Utf8,
            bom_stripped: false,
            pending: Vec::new(),
        }
    }

    fn with_encoding(encoding: Encoding) -> Self {
        Self {
            encoding,
            bom_stripped: false,
            pending: Vec::new(),
        }
    }

    /// Lossy streaming decode (TextDecoder without `fatal`). Incomplete trailing
    /// multibyte sequences are retained for the next call.
    fn decode_stream(&mut self, bytes: &[u8]) -> String {
        let mut buffer = std::mem::take(&mut self.pending);
        buffer.extend_from_slice(bytes);
        let buffer = self.strip_bom(buffer);
        match self.encoding {
            Encoding::Utf8 => {
                let (text, remainder) = decode_utf8_stream(&buffer, false);
                self.pending = remainder;
                text
            }
            Encoding::Utf16Le | Encoding::Utf16Be => {
                let (text, remainder) = decode_utf16_stream(&buffer, self.encoding, false);
                self.pending = remainder;
                text
            }
        }
    }

    /// Fatal streaming decode (TextDecoder with `{ fatal: true }`). Returns Err
    /// when an invalid sequence is observed. Incomplete trailing sequences do
    /// not fail in streaming mode.
    fn decode_stream_fatal(&mut self, bytes: &[u8]) -> Result<(), ()> {
        let mut buffer = std::mem::take(&mut self.pending);
        buffer.extend_from_slice(bytes);
        let buffer = self.strip_bom(buffer);
        match self.encoding {
            Encoding::Utf8 => {
                let (valid, remainder, ok) = validate_utf8_stream(&buffer);
                self.pending = remainder;
                let _ = valid;
                if ok { Ok(()) } else { Err(()) }
            }
            Encoding::Utf16Le | Encoding::Utf16Be => {
                // UTF-16 streaming only has incomplete-unit remainders; unpaired
                // surrogates decode to U+FFFD even in fatal mode in WHATWG, so
                // this never fails for the bytes used here.
                let remainder = buffer.len() % 2;
                let keep = buffer.len() - remainder;
                self.pending = buffer[keep..].to_vec();
                Ok(())
            }
        }
    }

    fn strip_bom(&mut self, buffer: Vec<u8>) -> Vec<u8> {
        if self.bom_stripped {
            return buffer;
        }
        match self.encoding {
            Encoding::Utf8 => {
                if buffer.len() >= 3 && buffer[0..3] == [0xef, 0xbb, 0xbf] {
                    self.bom_stripped = true;
                    return buffer[3..].to_vec();
                }
                if buffer.len() >= 3 {
                    self.bom_stripped = true;
                }
                buffer
            }
            Encoding::Utf16Le => {
                if buffer.len() >= 2 && buffer[0] == 0xff && buffer[1] == 0xfe {
                    self.bom_stripped = true;
                    return buffer[2..].to_vec();
                }
                if buffer.len() >= 2 {
                    self.bom_stripped = true;
                }
                buffer
            }
            Encoding::Utf16Be => {
                if buffer.len() >= 2 && buffer[0] == 0xfe && buffer[1] == 0xff {
                    self.bom_stripped = true;
                    return buffer[2..].to_vec();
                }
                if buffer.len() >= 2 {
                    self.bom_stripped = true;
                }
                buffer
            }
        }
    }
}

/// Lossy UTF-8 stream decode: returns decoded text and leftover trailing bytes
/// that form an incomplete multibyte sequence.
fn decode_utf8_stream(bytes: &[u8], _flush: bool) -> (String, Vec<u8>) {
    let complete = utf8_complete_len(bytes);
    let text = String::from_utf8_lossy(&bytes[..complete]).into_owned();
    (text, bytes[complete..].to_vec())
}

/// Fatal UTF-8 validation. Returns `(valid_prefix_len, remainder, ok)`.
fn validate_utf8_stream(bytes: &[u8]) -> (usize, Vec<u8>, bool) {
    let complete = utf8_complete_len(bytes);
    let ok = std::str::from_utf8(&bytes[..complete]).is_ok();
    (complete, bytes[complete..].to_vec(), ok)
}

/// Length of the prefix of `bytes` that excludes an incomplete trailing UTF-8
/// multibyte sequence. The returned prefix may still contain invalid bytes.
fn utf8_complete_len(bytes: &[u8]) -> usize {
    let len = bytes.len();
    // Walk back over trailing continuation bytes to find a lead byte.
    let mut index = len;
    let mut continuations = 0usize;
    while index > 0 {
        let byte = bytes[index - 1];
        if byte & 0b1100_0000 == 0b1000_0000 {
            continuations += 1;
            index -= 1;
            if continuations >= 3 {
                break;
            }
            continue;
        }
        // Lead byte or ASCII at index-1.
        let expected = if byte & 0b1000_0000 == 0 {
            1
        } else if byte & 0b1110_0000 == 0b1100_0000 {
            2
        } else if byte & 0b1111_0000 == 0b1110_0000 {
            3
        } else if byte & 0b1111_1000 == 0b1111_0000 {
            4
        } else {
            1
        };
        let have = continuations + 1;
        if expected > have {
            // Incomplete sequence: keep it pending.
            return index - 1;
        }
        return len;
    }
    len
}

/// Lossy UTF-16 stream decode for the little/big encodings used here.
fn decode_utf16_stream(bytes: &[u8], encoding: Encoding, _flush: bool) -> (String, Vec<u8>) {
    let remainder = bytes.len() % 2;
    let keep = bytes.len() - remainder;
    let mut units: Vec<u16> = Vec::with_capacity(keep / 2);
    let mut index = 0;
    while index + 1 < keep + 1 && index + 1 < bytes.len() {
        if index + 2 > keep {
            break;
        }
        let unit = match encoding {
            Encoding::Utf16Le => u16::from_le_bytes([bytes[index], bytes[index + 1]]),
            Encoding::Utf16Be => u16::from_be_bytes([bytes[index], bytes[index + 1]]),
            Encoding::Utf8 => unreachable!(),
        };
        units.push(unit);
        index += 2;
    }
    let text = String::from_utf16_lossy(&units);
    (text, bytes[keep..].to_vec())
}

// ----- XML plist prolog scanner (TS createXmlPlistPrologScanner) -----

struct ScanResult {
    state: XmlPlistProbeState,
    /// Number of UTF-16 code units consumed from the aggregate stream.
    consumed: usize,
}

enum Pending {
    None,
    QuestionGt,
    CommentEnd,
}

/// Stateful prolog scanner operating on JS string semantics (UTF-16 code
/// units). Rust `char` differs from a UTF-16 code unit only for astral code
/// points, which never appear in an XML prolog token, so operating over
/// `Vec<char>` is faithful for the tokens inspected here while keeping offsets
/// exact for the ASCII whitespace and markup compared.
struct PrologScanner {
    text: Vec<char>,
    total_characters: usize,
    pending: Pending,
    doctype_name: bool,
}

impl PrologScanner {
    fn new() -> Self {
        Self {
            text: Vec::new(),
            total_characters: 0,
            pending: Pending::None,
            doctype_name: false,
        }
    }

    fn scan(&mut self, chunk: &str) -> ScanResult {
        // JS counts UTF-16 code units; use char count, which matches for the
        // ASCII prolog tokens this scanner recognizes.
        let chunk_units: Vec<char> = chunk.chars().collect();
        let before = self.total_characters;
        self.total_characters += chunk_units.len();
        self.text.extend_from_slice(&chunk_units);
        let mut cursor = 0usize;

        let make_result = |scanner: &PrologScanner, state, through: usize| ScanResult {
            state,
            consumed: scanner.total_characters - scanner.text.len() + through - before,
        };

        loop {
            match self.pending {
                Pending::None => {}
                _ => {
                    let terminator: &[char] = match self.pending {
                        Pending::QuestionGt => &['?', '>'],
                        Pending::CommentEnd => &['-', '-', '>'],
                        Pending::None => unreachable!(),
                    };
                    match find_subslice(&self.text, cursor, terminator) {
                        None => {
                            let keep = std::cmp::max(
                                cursor,
                                self.text.len().saturating_sub(terminator.len() - 1),
                            );
                            self.text.drain(0..keep);
                            return make_result(self, XmlPlistProbeState::Pending, 0);
                        }
                        Some(end) => {
                            cursor = end + terminator.len();
                            self.pending = Pending::None;
                        }
                    }
                }
            }

            while cursor < self.text.len() && is_xml_whitespace(self.text[cursor]) {
                cursor += 1;
            }
            if cursor == self.text.len() {
                self.text.clear();
                return make_result(self, XmlPlistProbeState::Pending, 0);
            }

            if self.doctype_name {
                let token = token_at(&self.text, cursor, "plist");
                if token == TokenMatch::Partial
                    || (token == TokenMatch::Match && cursor + 5 == self.text.len())
                {
                    self.text.drain(0..cursor);
                    return make_result(self, XmlPlistProbeState::Pending, 0);
                }
                let delimiter = self.text.get(cursor + 5).copied();
                let matched = token == TokenMatch::Match
                    && matches!(delimiter, Some('>') | Some('['))
                    || (token == TokenMatch::Match && delimiter.is_some_and(is_xml_whitespace));
                let through = cursor + 6;
                return make_result(
                    self,
                    if matched {
                        XmlPlistProbeState::Matched
                    } else {
                        XmlPlistProbeState::Rejected
                    },
                    through,
                );
            }

            // [("<!--", "-->"), ("<?", "?>")]
            let mut broke_to_pending = false;
            for (token, terminator) in [("<!--", Pending::CommentEnd), ("<?", Pending::QuestionGt)]
            {
                let token_chars: Vec<char> = token.chars().collect();
                let m = token_at(&self.text, cursor, token);
                if m == TokenMatch::Partial {
                    self.text.drain(0..cursor);
                    return make_result(self, XmlPlistProbeState::Pending, 0);
                }
                if m == TokenMatch::Match {
                    self.pending = terminator;
                    cursor += token_chars.len();
                    broke_to_pending = true;
                    break;
                }
            }
            if broke_to_pending {
                continue;
            }

            let doctype = token_at(&self.text, cursor, "<!DOCTYPE");
            if doctype == TokenMatch::Partial
                || (doctype == TokenMatch::Match && cursor + 9 == self.text.len())
            {
                self.text.drain(0..cursor);
                return make_result(self, XmlPlistProbeState::Pending, 0);
            }
            if doctype == TokenMatch::Match {
                match self.text.get(cursor + 9).copied() {
                    Some(character) if is_xml_whitespace(character) => {}
                    _ => return make_result(self, XmlPlistProbeState::Rejected, cursor),
                }
                cursor += 10;
                self.doctype_name = true;
                continue;
            }

            let root = token_at(&self.text, cursor, "<plist");
            if root == TokenMatch::Partial
                || (root == TokenMatch::Match && cursor + 6 == self.text.len())
            {
                self.text.drain(0..cursor);
                return make_result(self, XmlPlistProbeState::Pending, 0);
            }
            let delimiter = self.text.get(cursor + 6).copied();
            let matched = root == TokenMatch::Match
                && (matches!(delimiter, Some('/') | Some('>'))
                    || delimiter.is_some_and(is_xml_whitespace));
            let through = cursor + 7;
            return make_result(
                self,
                if matched {
                    XmlPlistProbeState::Matched
                } else {
                    XmlPlistProbeState::Rejected
                },
                through,
            );
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TokenMatch {
    Match,
    Partial,
    None,
}

/// TS `tokenAt(text, offset, token)`.
fn token_at(text: &[char], offset: usize, token: &str) -> TokenMatch {
    let token_chars: Vec<char> = token.chars().collect();
    let end = std::cmp::min(offset + token_chars.len(), text.len());
    let available = &text[offset.min(text.len())..end];
    if available == token_chars.as_slice() {
        TokenMatch::Match
    } else if token_chars.starts_with(available) {
        TokenMatch::Partial
    } else {
        TokenMatch::None
    }
}

fn is_xml_whitespace(character: char) -> bool {
    matches!(character, ' ' | '\t' | '\r' | '\n')
}

/// Find `needle` in `haystack[from..]`, returning the absolute start index.
fn find_subslice(haystack: &[char], from: usize, needle: &[char]) -> Option<usize> {
    if needle.is_empty() || from > haystack.len() {
        return None;
    }
    haystack[from..]
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|position| from + position)
}

/// TS `createXmlPlistSignatureProbe().write(bytes) === "matched"`.
#[allow(dead_code)]
pub(crate) fn has_xml_plist_signature(bytes: &[u8]) -> bool {
    XmlPlistSignatureProbe::new().write(bytes) == XmlPlistProbeState::Matched
}
