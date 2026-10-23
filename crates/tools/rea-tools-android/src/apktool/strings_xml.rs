//! Decoded Android string-resource projection.
//!
//! Compatibility owner: `parseDecodedStrings` in
//! `src/apktool/ApktoolDecodeOutput.ts`. Direct `<string>` children of the
//! `<resources>` root are projected; text values keep their source entity
//! spelling and whitespace (sliced from the input up to the next `<`), and
//! markup-bearing or unnamed entries are omitted and counted.

/// One projected string entry (`DecodedStringEntry`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedStringEntry {
    pub name: String,
    pub value: String,
}

/// Why a whole string document could not be projected
/// (`ApktoolStringsDocumentError`). Only the message is published; the malformed
/// and wrong-root cases are not distinguished downstream.
#[derive(Debug)]
pub struct DocumentError {
    pub message: String,
}

/// Projected entries with the count of omitted ones.
pub struct ParsedStrings {
    pub entries: Vec<DecodedStringEntry>,
    pub unparsed_count: u64,
}

/// `parseDecodedStrings(stringsXml)`.
pub fn parse_decoded_strings(source: &str) -> Result<ParsedStrings, DocumentError> {
    let mut scanner = Scanner::new(source);
    scanner.skip_prolog()?;

    // The document element must be <resources>.
    let root = scanner.read_start_tag().ok_or_else(malformed)?;
    if root.name != "resources" {
        return Err(DocumentError {
            message: "String resource document root must be <resources>".into(),
        });
    }
    if root.self_closing {
        return Ok(ParsedStrings {
            entries: Vec::new(),
            unparsed_count: 0,
        });
    }

    let mut entries: Vec<DecodedStringEntry> = Vec::new();
    let mut unparsed_count: u64 = 0;

    loop {
        scanner.skip_text();
        if scanner.at_end() {
            // Reached EOF without a balanced </resources>; the DOM parser would
            // reject this as malformed.
            return Err(malformed());
        }
        if scanner.peek_close_tag("resources") {
            break;
        }
        if scanner.peek_comment() {
            scanner.skip_comment().ok_or_else(malformed)?;
            continue;
        }
        if scanner.peek_cdata() {
            // CDATA between elements is ignored by direct-child element scanning.
            scanner.skip_cdata().ok_or_else(malformed)?;
            continue;
        }
        // A direct child element.
        let tag = scanner.read_start_tag().ok_or_else(malformed)?;
        if tag.name != "string" {
            // Skip a non-<string> direct child and its subtree.
            if !tag.self_closing {
                scanner.skip_element(&tag.name).ok_or_else(malformed)?;
            }
            continue;
        }
        let name = tag.attribute("name");
        if tag.self_closing {
            match name {
                Some(name) if !name.is_empty() => entries.push(DecodedStringEntry {
                    name,
                    value: String::new(),
                }),
                _ => unparsed_count += 1,
            }
            continue;
        }
        match project_string(&mut scanner, name)? {
            Some(entry) => entries.push(entry),
            None => unparsed_count += 1,
        }
    }

    Ok(ParsedStrings {
        entries,
        unparsed_count,
    })
}

fn malformed() -> DocumentError {
    DocumentError {
        message: "String resource document is not well-formed XML".into(),
    }
}

/// Project one `<string name=...>...</string>` body. Returns `None` when the
/// entry is omitted (missing name, or non-text/comment content).
fn project_string(
    scanner: &mut Scanner<'_>,
    name: Option<String>,
) -> Result<Option<DecodedStringEntry>, DocumentError> {
    // Collect the raw text segments and observe whether non-text/comment
    // content appears, scanning to the closing </string>.
    let mut value = String::new();
    let mut only_comments = true;
    let mut had_text = false;
    let mut rejected = false;
    loop {
        if scanner.at_end() {
            return Err(malformed());
        }
        if scanner.peek_close_tag("string") {
            scanner.consume_close_tag("string").ok_or_else(malformed)?;
            break;
        }
        if scanner.peek_comment() {
            scanner.skip_comment().ok_or_else(malformed)?;
            continue;
        }
        if scanner.peek_element_start() || scanner.peek_cdata() {
            // A nested element or CDATA section: this value is not plain text.
            rejected = true;
            only_comments = false;
            if scanner.peek_cdata() {
                scanner.skip_cdata().ok_or_else(malformed)?;
            } else {
                let tag = scanner.read_start_tag().ok_or_else(malformed)?;
                if !tag.self_closing {
                    scanner.skip_element(&tag.name).ok_or_else(malformed)?;
                }
            }
            continue;
        }
        // A run of text up to the next '<'.
        let text = scanner.read_text_until_markup();
        if !text.is_empty() {
            had_text = true;
            only_comments = false;
            value.push_str(&decode_text(text));
        }
    }

    let Some(name) = name.filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    if rejected {
        return Ok(None);
    }
    if !had_text && only_comments {
        return Ok(Some(DecodedStringEntry {
            name,
            value: String::new(),
        }));
    }
    Ok(Some(DecodedStringEntry { name, value }))
}

/// Decode XML entities inside string text, preserving surrounding spelling.
fn decode_text(text: &str) -> String {
    super::decode_output::decode_xml_entities(text)
}

/// A minimal forward XML scanner over a decoded resources document.
struct Scanner<'a> {
    source: &'a str,
    bytes: &'a [u8],
    index: usize,
}

struct StartTag {
    name: String,
    attributes: Vec<(String, String)>,
    self_closing: bool,
}

impl StartTag {
    fn attribute(&self, name: &str) -> Option<String> {
        self.attributes
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
    }
}

impl<'a> Scanner<'a> {
    fn new(source: &'a str) -> Self {
        let mut index = 0;
        let bytes = source.as_bytes();
        if bytes.len() >= 3 && bytes[..3] == [0xef, 0xbb, 0xbf] {
            index = 3;
        }
        Self {
            source,
            bytes,
            index,
        }
    }

    fn at_end(&self) -> bool {
        self.index >= self.bytes.len()
    }

    fn skip_prolog(&mut self) -> Result<(), DocumentError> {
        loop {
            self.skip_whitespace();
            if self.at_end() {
                return Err(malformed());
            }
            if self.source[self.index..].starts_with("<?") {
                let end = self.source[self.index..].find("?>").ok_or_else(malformed)?;
                self.index += end + 2;
            } else if self.source[self.index..].starts_with("<!--") {
                self.skip_comment().ok_or_else(malformed)?;
            } else if self.source[self.index..].starts_with("<!") {
                self.index = skip_declaration(self.source, self.index).ok_or_else(malformed)?;
            } else {
                return Ok(());
            }
        }
    }

    fn skip_whitespace(&mut self) {
        while self.index < self.bytes.len()
            && matches!(self.bytes[self.index], b' ' | b'\t' | b'\r' | b'\n')
        {
            self.index += 1;
        }
    }

    fn skip_text(&mut self) {
        while self.index < self.bytes.len() && self.bytes[self.index] != b'<' {
            self.index += 1;
        }
    }

    fn read_text_until_markup(&mut self) -> &'a str {
        let start = self.index;
        while self.index < self.bytes.len() && self.bytes[self.index] != b'<' {
            self.index += 1;
        }
        &self.source[start..self.index]
    }

    fn peek_comment(&self) -> bool {
        self.source[self.index..].starts_with("<!--")
    }

    fn peek_cdata(&self) -> bool {
        self.source[self.index..].starts_with("<![CDATA[")
    }

    fn peek_element_start(&self) -> bool {
        let rest = &self.source[self.index..];
        rest.starts_with('<')
            && !rest.starts_with("</")
            && !rest.starts_with("<!")
            && !rest.starts_with("<?")
    }

    fn peek_close_tag(&self, name: &str) -> bool {
        let rest = &self.source[self.index..];
        if !rest.starts_with("</") {
            return false;
        }
        let after = &rest[2..];
        after.starts_with(name) && after[name.len()..].trim_start().starts_with('>')
    }

    fn consume_close_tag(&mut self, name: &str) -> Option<()> {
        let rest = &self.source[self.index..];
        if !rest.starts_with("</") {
            return None;
        }
        let end = rest.find('>')?;
        let inner = rest[2..end].trim();
        if inner != name {
            return None;
        }
        self.index += end + 1;
        Some(())
    }

    fn skip_comment(&mut self) -> Option<()> {
        let rest = &self.source[self.index..];
        if !rest.starts_with("<!--") {
            return None;
        }
        let end = rest[4..].find("-->")?;
        self.index += 4 + end + 3;
        Some(())
    }

    fn skip_cdata(&mut self) -> Option<()> {
        let rest = &self.source[self.index..];
        if !rest.starts_with("<![CDATA[") {
            return None;
        }
        let end = rest[9..].find("]]>")?;
        self.index += 9 + end + 3;
        Some(())
    }

    fn read_start_tag(&mut self) -> Option<StartTag> {
        let bytes = self.bytes;
        if self.index >= bytes.len() || bytes[self.index] != b'<' {
            return None;
        }
        let mut index = self.index + 1;
        let name_start = index;
        while index < bytes.len() && !is_name_delimiter(bytes[index]) {
            index += 1;
        }
        if index == name_start {
            return None;
        }
        let name = self.source[name_start..index].to_owned();
        let mut attributes: Vec<(String, String)> = Vec::new();
        let mut self_closing = false;
        loop {
            while index < bytes.len() && matches!(bytes[index], b' ' | b'\t' | b'\r' | b'\n') {
                index += 1;
            }
            if index >= bytes.len() {
                return None;
            }
            if bytes[index] == b'>' {
                index += 1;
                break;
            }
            if bytes[index] == b'/' {
                if self.source[index..].starts_with("/>") {
                    self_closing = true;
                    index += 2;
                    break;
                }
                return None;
            }
            let attr_start = index;
            while index < bytes.len()
                && !matches!(
                    bytes[index],
                    b'=' | b' ' | b'\t' | b'\r' | b'\n' | b'>' | b'/'
                )
            {
                index += 1;
            }
            if index == attr_start {
                return None;
            }
            let attr_name = self.source[attr_start..index].to_owned();
            while index < bytes.len() && matches!(bytes[index], b' ' | b'\t' | b'\r' | b'\n') {
                index += 1;
            }
            if index >= bytes.len() || bytes[index] != b'=' {
                return None;
            }
            index += 1;
            while index < bytes.len() && matches!(bytes[index], b' ' | b'\t' | b'\r' | b'\n') {
                index += 1;
            }
            if index >= bytes.len() || !matches!(bytes[index], b'"' | b'\'') {
                return None;
            }
            let quote = bytes[index];
            index += 1;
            let value_start = index;
            while index < bytes.len() && bytes[index] != quote {
                index += 1;
            }
            if index >= bytes.len() {
                return None;
            }
            let raw = &self.source[value_start..index];
            index += 1;
            attributes.push((attr_name, super::decode_output::decode_xml_entities(raw)));
        }
        self.index = index;
        Some(StartTag {
            name,
            attributes,
            self_closing,
        })
    }

    /// Skip a child element and its entire subtree given its start tag name.
    fn skip_element(&mut self, name: &str) -> Option<()> {
        let mut depth = 1usize;
        while depth > 0 {
            if self.at_end() {
                return None;
            }
            if self.peek_comment() {
                self.skip_comment()?;
                continue;
            }
            if self.peek_cdata() {
                self.skip_cdata()?;
                continue;
            }
            if self.source[self.index..].starts_with("</") {
                let rest = &self.source[self.index..];
                let end = rest.find('>')?;
                let inner = rest[2..end].trim();
                self.index += end + 1;
                if inner == name {
                    depth -= 1;
                }
                continue;
            }
            if self.peek_element_start() {
                let tag = self.read_start_tag()?;
                if !tag.self_closing && tag.name == name {
                    depth += 1;
                } else if !tag.self_closing {
                    // A differently named nested element; recurse by name.
                    self.skip_element(&tag.name)?;
                }
                continue;
            }
            // Text content.
            self.skip_text();
        }
        Some(())
    }
}

fn is_name_delimiter(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\r' | b'\n' | b'>' | b'/')
}

fn skip_declaration(source: &str, start: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut index = start;
    let mut depth = 0i32;
    while index < bytes.len() {
        match bytes[index] {
            b'[' => depth += 1,
            b']' => depth -= 1,
            b'>' if depth <= 0 => return Some(index + 1),
            _ => {}
        }
        index += 1;
    }
    None
}
