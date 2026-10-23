//! Parsers for Apktool's decoded output documents.
//!
//! Compatibility owner: `src/apktool/ApktoolDecodeOutput.ts`. Values are read
//! from `apktool.yml`, `AndroidManifest.xml` and `res/.../strings.xml`.
//! Version codes keep the exact spelling Apktool emitted; string values keep
//! their source entity spelling and whitespace, and markup-bearing entries are
//! omitted and counted as partial evidence.

/// Projected Apktool metadata fields (`ApktoolMetadata`).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ApktoolMetadata {
    pub version_name: Option<String>,
    pub version_code: Option<String>,
    pub min_sdk_version: Option<String>,
    pub target_sdk_version: Option<String>,
}

/// A malformed metadata document (`TypeError` in the TS producer).
#[derive(Debug)]
pub struct MetadataError {
    pub message: String,
}

/// `parseApktoolYml(yml)`: read the published fields from the tagged metadata
/// mapping. The document is a block mapping of scalar or nested-mapping values
/// as Apktool's `MetaInfo` serializer emits; a non-mapping root is rejected.
pub fn parse_apktool_yml(yml: &str) -> Result<ApktoolMetadata, MetadataError> {
    let mapping = parse_block_mapping(yml)?;
    Ok(ApktoolMetadata {
        version_name: mapping.nested_scalar("versionInfo", "versionName"),
        version_code: mapping.nested_scalar("versionInfo", "versionCode"),
        min_sdk_version: mapping.nested_scalar("sdkInfo", "minSdkVersion"),
        target_sdk_version: mapping.nested_scalar("sdkInfo", "targetSdkVersion"),
    })
}

/// A two-level block mapping: top-level keys to either a scalar or a nested
/// mapping of scalars.
struct BlockMapping {
    entries: Vec<(String, MappingValue)>,
}

enum MappingValue {
    /// A scalar value. Top-level scalars are not among the published fields,
    /// so their text is not retained.
    Scalar,
    /// A nested mapping of scalar values.
    Nested(Vec<(String, Option<String>)>),
}

impl BlockMapping {
    fn nested_scalar(&self, parent: &str, child: &str) -> Option<String> {
        let value = self
            .entries
            .iter()
            .find(|(key, _)| key == parent)
            .map(|(_, value)| value)?;
        match value {
            MappingValue::Nested(children) => children
                .iter()
                .find(|(key, _)| key == child)
                .and_then(|(_, scalar)| scalar.clone()),
            MappingValue::Scalar => None,
        }
    }
}

/// Column (in spaces) of the first non-space byte, or `None` for a blank line.
fn indentation(line: &str) -> Option<usize> {
    let trimmed = line.trim_start_matches(' ');
    if trimmed.is_empty() {
        None
    } else {
        Some(line.len() - trimmed.len())
    }
}

fn parse_block_mapping(yml: &str) -> Result<BlockMapping, MetadataError> {
    let mut entries: Vec<(String, MappingValue)> = Vec::new();
    let lines: Vec<&str> = yml
        .split('\n')
        .map(|line| line.trim_end_matches('\r'))
        .collect();
    let mut index = 0;
    let mut saw_mapping = false;
    while index < lines.len() {
        let line = lines[index];
        let content = strip_comment(line);
        if content.trim().is_empty() || is_directive(content) {
            index += 1;
            continue;
        }
        let indent = indentation(content).unwrap_or(0);
        if indent != 0 {
            // Unexpected leading indentation at the document root.
            return Err(MetadataError {
                message: "apktool.yml root must be an Apktool metadata mapping".into(),
            });
        }
        let (key, inline) = split_key_value(content.trim_start()).ok_or_else(|| MetadataError {
            message: "apktool.yml root must be an Apktool metadata mapping".into(),
        })?;
        saw_mapping = true;
        match inline {
            Some(_) => {
                entries.push((key, MappingValue::Scalar));
                index += 1;
            }
            None => {
                // Collect a nested mapping from the following more-indented lines.
                let mut children: Vec<(String, Option<String>)> = Vec::new();
                index += 1;
                while index < lines.len() {
                    let nested = strip_comment(lines[index]);
                    if nested.trim().is_empty() {
                        index += 1;
                        continue;
                    }
                    match indentation(nested) {
                        Some(child_indent) if child_indent > 0 => {
                            if let Some((child_key, child_value)) =
                                split_key_value(nested.trim_start())
                            {
                                children.push((
                                    child_key,
                                    child_value.as_deref().and_then(normalize_scalar),
                                ));
                            }
                            index += 1;
                        }
                        _ => break,
                    }
                }
                entries.push((key, MappingValue::Nested(children)));
            }
        }
    }
    if !saw_mapping {
        return Err(MetadataError {
            message: "apktool.yml root must be an Apktool metadata mapping".into(),
        });
    }
    Ok(BlockMapping { entries })
}

fn is_directive(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("---") || trimmed.starts_with("!!") || trimmed.starts_with('%')
}

fn strip_comment(line: &str) -> &str {
    // A comment begins at an unquoted '#' preceded by whitespace or line start.
    let bytes = line.as_bytes();
    let mut in_single = false;
    let mut in_double = false;
    for (index, &byte) in bytes.iter().enumerate() {
        match byte {
            b'\'' if !in_double => in_single = !in_single,
            b'"' if !in_single => in_double = !in_double,
            b'#' if !in_single && !in_double => {
                if index == 0 || bytes[index - 1] == b' ' || bytes[index - 1] == b'\t' {
                    return &line[..index];
                }
            }
            _ => {}
        }
    }
    line
}

/// Split `key: value` into the key and the inline value text (None when the
/// value opens a nested block).
fn split_key_value(text: &str) -> Option<(String, Option<String>)> {
    let position = find_key_colon(text)?;
    let key = text[..position].trim().to_owned();
    if key.is_empty() {
        return None;
    }
    let value = text[position + 1..].trim();
    if value.is_empty() {
        Some((key, None))
    } else {
        Some((key, Some(value.to_owned())))
    }
}

fn find_key_colon(text: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut in_single = false;
    let mut in_double = false;
    for (index, &byte) in bytes.iter().enumerate() {
        match byte {
            b'\'' if !in_double => in_single = !in_single,
            b'"' if !in_single => in_double = !in_double,
            b':' if !in_single && !in_double => {
                // A mapping colon is followed by a space or ends the line.
                if index + 1 == bytes.len() || bytes[index + 1] == b' ' {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
}

/// Normalize a scalar: explicit null (`null`, `~`, empty) becomes `None`;
/// quoted strings return their inner content; plain scalars return as written.
fn normalize_scalar(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed == "~"
        || trimmed == "null"
        || trimmed == "Null"
        || trimmed == "NULL"
    {
        return None;
    }
    if trimmed.len() >= 2 && trimmed.starts_with('\'') && trimmed.ends_with('\'') {
        return Some(trimmed[1..trimmed.len() - 1].replace("''", "'"));
    }
    if trimmed.len() >= 2 && trimmed.starts_with('"') && trimmed.ends_with('"') {
        return Some(unescape_double_quoted(&trimmed[1..trimmed.len() - 1]));
    }
    Some(trimmed.to_owned())
}

fn unescape_double_quoted(value: &str) -> String {
    let mut result = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(character) = chars.next() {
        if character == '\\' {
            match chars.next() {
                Some('n') => result.push('\n'),
                Some('t') => result.push('\t'),
                Some('r') => result.push('\r'),
                Some('"') => result.push('"'),
                Some('\\') => result.push('\\'),
                Some(other) => {
                    result.push('\\');
                    result.push(other);
                }
                None => result.push('\\'),
            }
        } else {
            result.push(character);
        }
    }
    result
}

/// `parseManifestPackage(manifest)`: read the `package` attribute of the
/// `<manifest>` root element. A non-well-formed document or a wrong root is a
/// producer failure.
pub fn parse_manifest_package(manifest: &str) -> Result<Option<String>, MetadataError> {
    let root = find_root_element(manifest).ok_or_else(|| MetadataError {
        message: "AndroidManifest.xml is not well-formed XML".into(),
    })?;
    if root.name != "manifest" {
        return Err(MetadataError {
            message: "AndroidManifest.xml root must be <manifest>".into(),
        });
    }
    Ok(root.attribute("package").filter(|value| !value.is_empty()))
}

/// The opening tag of the document element with its attributes.
struct RootElement {
    name: String,
    attributes: Vec<(String, String)>,
}

impl RootElement {
    fn attribute(&self, name: &str) -> Option<String> {
        self.attributes
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
    }
}

/// Find the first element start tag, skipping prolog, comments, PIs and the
/// doctype. Returns `None` when no element is found.
fn find_root_element(source: &str) -> Option<RootElement> {
    let bytes = source.as_bytes();
    let mut index = 0;
    // Skip an optional UTF-8 BOM.
    if bytes.len() >= 3 && bytes[..3] == [0xef, 0xbb, 0xbf] {
        index = 3;
    }
    while index < bytes.len() {
        match bytes[index] {
            b' ' | b'\t' | b'\r' | b'\n' => {
                index += 1;
            }
            b'<' => {
                if source[index..].starts_with("<?") {
                    let end = source[index..].find("?>")? + index + 2;
                    index = end;
                } else if source[index..].starts_with("<!--") {
                    let end = source[index + 4..].find("-->")? + index + 4 + 3;
                    index = end;
                } else if source[index..].starts_with("<!") {
                    // DOCTYPE or other declaration: skip to its closing '>',
                    // tolerating an internal subset bracketed by [ ].
                    index = skip_declaration(source, index)?;
                } else {
                    return parse_start_tag(source, index);
                }
            }
            _ => return None,
        }
    }
    None
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

fn parse_start_tag(source: &str, start: usize) -> Option<RootElement> {
    let bytes = source.as_bytes();
    let mut index = start + 1;
    let name_start = index;
    while index < bytes.len() && !is_tag_delimiter(bytes[index]) {
        index += 1;
    }
    if index == name_start {
        return None;
    }
    let name = source[name_start..index].to_owned();
    let mut attributes: Vec<(String, String)> = Vec::new();
    loop {
        while index < bytes.len() && matches!(bytes[index], b' ' | b'\t' | b'\r' | b'\n') {
            index += 1;
        }
        if index >= bytes.len() {
            return None;
        }
        if bytes[index] == b'>' || (bytes[index] == b'/' && source[index..].starts_with("/>")) {
            break;
        }
        // Attribute name.
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
        let attr_name = source[attr_start..index].to_owned();
        while index < bytes.len() && matches!(bytes[index], b' ' | b'\t' | b'\r' | b'\n') {
            index += 1;
        }
        if index >= bytes.len() || bytes[index] != b'=' {
            // Attribute without a value is not valid in these documents.
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
        let raw = &source[value_start..index];
        index += 1;
        attributes.push((attr_name, decode_xml_entities(raw)));
    }
    Some(RootElement { name, attributes })
}

fn is_tag_delimiter(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\r' | b'\n' | b'>' | b'/')
}

/// Decode the XML predefined entities and numeric character references used in
/// well-formed attribute values.
pub fn decode_xml_entities(value: &str) -> String {
    if !value.contains('&') {
        return value.to_owned();
    }
    let mut result = String::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'&' {
            if let Some(end) = value[index..].find(';') {
                let entity = &value[index + 1..index + end];
                if let Some(decoded) = decode_entity(entity) {
                    result.push(decoded);
                    index += end + 1;
                    continue;
                }
            }
        }
        let character_len = utf8_char_len(bytes[index]);
        result.push_str(&value[index..index + character_len]);
        index += character_len;
    }
    result
}

fn decode_entity(entity: &str) -> Option<char> {
    match entity {
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        _ => {
            if let Some(hex) = entity
                .strip_prefix("#x")
                .or_else(|| entity.strip_prefix("#X"))
            {
                u32::from_str_radix(hex, 16).ok().and_then(char::from_u32)
            } else if let Some(decimal) = entity.strip_prefix('#') {
                decimal.parse::<u32>().ok().and_then(char::from_u32)
            } else {
                None
            }
        }
    }
}

fn utf8_char_len(byte: u8) -> usize {
    if byte < 0x80 {
        1
    } else if byte >> 5 == 0b110 {
        2
    } else if byte >> 4 == 0b1110 {
        3
    } else {
        4
    }
}
