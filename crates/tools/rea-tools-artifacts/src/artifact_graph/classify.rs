//! Byte- and path-based artifact classification.
//!
//! Compatibility owners: `src/artifacts/inventory/ArtifactGraphConstruction.ts`
//! (`classifyArtifactBytes`, `classifyArtifactPath`, `classifyArtifactContent`,
//! `artifactRoleForFormat`), `src/domain/zipPackageFormat.ts`,
//! `src/domain/dosMz.ts`, `src/domain/apple/machoContainer.ts`,
//! `src/domain/apple/appleArchiveFormat.ts` (signature predicates) and
//! `src/domain/javascript/javascriptArtifactFiles.ts` (`isJavaScriptSourcePath`).
use super::asar::asar_header_matches;
use super::reader::ReaderFailure;
use rea_core::JsString;

/// Role of an occurrence: its artifact kind and format.
#[derive(Clone, Copy)]
pub struct Role {
    pub kind: &'static str,
    pub format: &'static str,
}

/// ZIP-backed application package families.
pub const ZIP_PACKAGE_FORMATS: [&str; 8] = [
    "zip", "ipa", "apk", "msix", "appx", "hap", "hsp", "app-pack",
];

pub fn is_zip_package_format(format: &str) -> bool {
    ZIP_PACKAGE_FORMATS.contains(&format)
}

/// `hasZipSignature`.
pub fn has_zip_signature(bytes: &[u8]) -> bool {
    bytes.len() >= 4
        && bytes[0] == 0x50
        && bytes[1] == 0x4b
        && ((bytes[2] == 0x03 && bytes[3] == 0x04)
            || (bytes[2] == 0x05 && bytes[3] == 0x06)
            || (bytes[2] == 0x07 && bytes[3] == 0x08))
}

/// `zipPackageFormatForPath` (extension-only).
pub fn zip_package_format_for_path(path: &str) -> Option<&'static str> {
    zip_package_format_for_js_path(&JsString::from(path))
}

pub fn zip_package_format_for_js_path(path: &JsString) -> Option<&'static str> {
    let lower = path.to_ascii_lowercase();
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

/// `ZIP_NON_ENTRY_LIMITATION`.
pub const ZIP_NON_ENTRY_LIMITATION: &str = "ZIP inventory lists central-directory entries only. Non-entry bytes, including an APK Signing Block before the central directory or a ZIP comment after it, are not occurrences.";

const BINARY_PLIST_MAGIC: [u8; 8] = [0x62, 0x70, 0x6c, 0x69, 0x73, 0x74, 0x30, 0x30];

pub fn has_binary_plist_signature(bytes: &[u8]) -> bool {
    bytes.len() >= 8 && bytes[..8] == BINARY_PLIST_MAGIC
}

/// `isJavaScriptSourcePath`.
pub fn is_javascript_source_path(path: &str) -> bool {
    is_javascript_source_js_path(&JsString::from(path))
}

fn is_javascript_source_js_path(path: &JsString) -> bool {
    let lower = path.to_ascii_lowercase();
    for ext in [".cjs", ".cts", ".mjs", ".mts", ".js", ".jsx", ".ts", ".tsx"] {
        if lower.ends_with(ext) {
            return true;
        }
    }
    false
}

/// `classifyArtifactPath`.
pub fn classify_artifact_path(path: &str) -> Role {
    classify_artifact_js_path(&JsString::from(path))
}

/// Classify a logical artifact path without requiring a valid UTF-8 view.
pub fn classify_artifact_js_path(path: &JsString) -> Role {
    let lower = path.to_ascii_lowercase();
    if lower.ends_with(".map") {
        return Role {
            kind: "source-map",
            format: "source-map",
        };
    }
    if is_javascript_source_js_path(path) {
        return Role {
            kind: "javascript",
            format: "javascript-bundle",
        };
    }
    if contains_ascii(&lower, ".framework/") || lower.ends_with(".framework") {
        return Role {
            kind: "framework",
            format: "file",
        };
    }
    if lower.ends_with(".node") {
        return Role {
            kind: "native-addon",
            format: "file",
        };
    }
    if lower.ends_with(".dylib") || lower.ends_with(".so") {
        return Role {
            kind: "dynamic-library",
            format: "file",
        };
    }
    if lower.ends_with(".plist") {
        return Role {
            kind: "plist",
            format: "plist",
        };
    }
    if lower.ends_with(".entitlements") {
        return Role {
            kind: "entitlements",
            format: "entitlements",
        };
    }
    Role {
        kind: "resource",
        format: "file",
    }
}

fn contains_ascii(path: &JsString, needle: &str) -> bool {
    let needle: Vec<u16> = needle.encode_utf16().collect();
    path.units()
        .windows(needle.len())
        .any(|window| window == needle)
}

/// `classifyArtifactBytes`.
pub fn classify_artifact_bytes(prefix: &[u8], file_size: u64) -> &'static str {
    if has_zip_signature(prefix) {
        return "zip";
    }
    if has_binary_plist_signature(prefix) {
        return "plist";
    }
    if has_xml_plist_signature(prefix) {
        return "plist";
    }
    if let Some(format) = classify_fat_artifact(prefix, file_size) {
        return format;
    }
    if prefix.len() >= 4 {
        let magic = u32::from_be_bytes([prefix[0], prefix[1], prefix[2], prefix[3]]);
        if [0xfeed_face, 0xfeed_facf, 0xcefa_edfe, 0xcffa_edfe].contains(&magic) {
            return "mach-o";
        }
        if prefix[..4] == [0x7f, 0x45, 0x4c, 0x46] {
            return "elf";
        }
    }
    if prefix.len() >= 2 && prefix[0] == 0x4d && prefix[1] == 0x5a {
        let prefix_len = prefix.len() as u64;
        if (file_size) < prefix_len || prefix_len < file_size.min(64) {
            return "unknown";
        }
        match observe_mz_windows_header(prefix, file_size) {
            MzObservation::SignatureNeeded => return "unknown",
            MzObservation::Declared { offset, signature } => {
                if signature == "PE" && offset >= 64 && offset <= prefix_len.saturating_sub(4) {
                    return "pe";
                }
                return "unknown";
            }
            _ => {}
        }
        if parse_dos_mz_valid(prefix, file_size) {
            return "dos-mz";
        }
        return "unknown";
    }
    "file"
}

/// `classifyArtifactContent`. `asar_header_matched` reports whether the ASAR
/// header signature probe observed a matched header over the prefix.
pub fn classify_artifact_content(
    path: &str,
    prefix: &[u8],
    file_size: u64,
) -> Result<Role, ReaderFailure> {
    classify_artifact_content_js_path(&JsString::from(path), prefix, file_size)
}

pub fn classify_artifact_content_js_path(
    path: &JsString,
    prefix: &[u8],
    file_size: u64,
) -> Result<Role, ReaderFailure> {
    let format = classify_artifact_bytes(prefix, file_size);
    let by_path = classify_artifact_js_path(path);
    let lower = path.to_ascii_lowercase();
    if format == "plist"
        && !has_binary_plist_signature(prefix)
        && (["javascript", "source-map", "entitlements"].contains(&by_path.kind)
            || lower.ends_with(".asar"))
    {
        return Ok(by_path);
    }
    if format == "file" && lower.ends_with(".asar") {
        match asar_header_matches(prefix, file_size) {
            AsarProbe::Limit => {
                return Err(ReaderFailure::new(
                    "limit",
                    "ASAR header exceeds the bounded classification or decode budget",
                ));
            }
            AsarProbe::Matched => {
                return Ok(Role {
                    kind: "container",
                    format: "asar",
                });
            }
            AsarProbe::Rejected => {}
        }
    }
    Ok(artifact_role_for_format_js_path(path, format))
}

/// Result of the ASAR header signature probe used during classification.
pub enum AsarProbe {
    Matched,
    Rejected,
    Limit,
}

fn artifact_role_for_format_js_path(path: &JsString, format: &'static str) -> Role {
    let by_path = classify_artifact_js_path(path);
    if format == "file" || format == by_path.format {
        return by_path;
    }
    if format == "unknown" {
        return Role {
            kind: "unknown",
            format,
        };
    }
    if format == "zip" {
        return Role {
            kind: "container",
            format: zip_package_format_for_js_path(path).unwrap_or(format),
        };
    }
    if format == "plist" {
        return Role {
            kind: "plist",
            format,
        };
    }
    Role {
        kind: if ["native-addon", "dynamic-library"].contains(&by_path.kind) {
            by_path.kind
        } else {
            "executable"
        },
        format,
    }
}

// --- DOS MZ / Windows header observation (subset of src/domain/dosMz.ts) ---

enum MzObservation {
    Absent,
    HeaderNeeded,
    SignatureNeeded,
    Declared {
        offset: u64,
        signature: &'static str,
    },
}

fn windows_header_signature(bytes: Option<&[u8]>) -> &'static str {
    let Some(bytes) = bytes else {
        return "unobserved";
    };
    if bytes.len() < 2 {
        return "unobserved";
    }
    let (first, second) = (bytes[0], bytes[1]);
    if first == 0x4e && second == 0x45 {
        return "NE";
    }
    if first == 0x4c && second == 0x45 {
        return "LE";
    }
    if first == 0x4c && second == 0x58 {
        return "LX";
    }
    if first != 0x50 || second != 0x45 {
        return "other";
    }
    if bytes.len() < 4 {
        return "unobserved";
    }
    if bytes[2] == 0 && bytes[3] == 0 {
        "PE"
    } else {
        "other"
    }
}

fn observe_mz_windows_header(bytes: &[u8], file_size: u64) -> MzObservation {
    if bytes.len() < 64 {
        return if file_size >= 64 {
            MzObservation::HeaderNeeded
        } else {
            MzObservation::Absent
        };
    }
    let header_bytes = u16::from_le_bytes([bytes[8], bytes[9]]) as u64 * 16;
    let relocation_count = u16::from_le_bytes([bytes[6], bytes[7]]) as u64;
    let table_start = u16::from_le_bytes([bytes[24], bytes[25]]) as u64;
    if header_bytes != 0
        && relocation_count > 0
        && table_start < 64
        && table_start + relocation_count * 4 > 60
    {
        return MzObservation::Absent;
    }
    let offset = u32::from_le_bytes([bytes[60], bytes[61], bytes[62], bytes[63]]) as u64;
    if offset == 0 {
        return MzObservation::Absent;
    }
    let inline_signature = if (offset as usize) < bytes.len() {
        let end = ((offset + 4) as usize).min(bytes.len());
        Some(&bytes[offset as usize..end])
    } else {
        None
    };
    let signature = windows_header_signature(inline_signature);
    if header_bytes == 0 || header_bytes >= 64 {
        return MzObservation::Declared { offset, signature };
    }
    if signature != "other" && signature != "unobserved" {
        return MzObservation::Declared { offset, signature };
    }
    if signature == "other" {
        return MzObservation::Absent;
    }
    let observed_pe_prefix = inline_signature
        .map(|s| s.len() >= 2 && &s[..2] == b"PE")
        .unwrap_or(false);
    if file_size.saturating_sub(offset) < if observed_pe_prefix { 4 } else { 2 } {
        return MzObservation::Absent;
    }
    MzObservation::SignatureNeeded
}

/// Minimal `parseDosMzHeader(...).ok` for classification. Reproduces the
/// structural validity gate without materializing the parsed header fields.
fn parse_dos_mz_valid(bytes: &[u8], file_size: u64) -> bool {
    if bytes.len() < 28 || &bytes[..2] != b"MZ" {
        return false;
    }
    if file_size < bytes.len() as u64 {
        return false;
    }
    match observe_mz_windows_header(bytes, file_size) {
        MzObservation::Declared { .. } | MzObservation::SignatureNeeded => return false,
        _ => {}
    }
    let last_page_bytes = u16::from_le_bytes([bytes[2], bytes[3]]) as u64;
    let pages = u16::from_le_bytes([bytes[4], bytes[5]]) as u64;
    if pages == 0 || last_page_bytes > 511 {
        return false;
    }
    let image_bytes = (pages - 1) * 512
        + if last_page_bytes == 0 {
            512
        } else {
            last_page_bytes
        };
    let header_bytes = u16::from_le_bytes([bytes[8], bytes[9]]) as u64 * 16;
    if header_bytes < 28 || header_bytes >= image_bytes {
        return false;
    }
    if image_bytes > file_size {
        return false;
    }
    let relocation_count = u16::from_le_bytes([bytes[6], bytes[7]]) as u64;
    let relocation_table_offset = u16::from_le_bytes([bytes[24], bytes[25]]) as u64;
    let table_end = relocation_table_offset + relocation_count * 4;
    if relocation_count > 0 && (relocation_table_offset < 28 || table_end > header_bytes) {
        return false;
    }
    if relocation_count > 0 && table_end > bytes.len() as u64 {
        return false;
    }
    if let MzObservation::HeaderNeeded = observe_mz_windows_header(bytes, file_size) {
        return false;
    }
    let module_bytes = image_bytes - header_bytes;
    for index in 0..relocation_count {
        let record = (relocation_table_offset + index * 4) as usize;
        if record + 4 > bytes.len() {
            return false;
        }
        let offset = u16::from_le_bytes([bytes[record], bytes[record + 1]]) as u64;
        let segment = u16::from_le_bytes([bytes[record + 2], bytes[record + 3]]) as u64;
        if segment * 16 + offset + 2 > module_bytes {
            return false;
        }
    }
    let entry_offset = u16::from_le_bytes([bytes[20], bytes[21]]) as u64;
    let entry_segment = u16::from_le_bytes([bytes[22], bytes[23]]) as u64;
    if entry_segment * 16 + entry_offset >= module_bytes {
        return false;
    }
    true
}

// --- Mach-O FAT container classification (subset of machoContainer.ts) ---

const FAT_MAGICS: [u32; 4] = [0xcafe_babe, 0xcafe_babf, 0xbeba_feca, 0xbfba_feca];
const MAX_FAT_ARCHITECTURES: u32 = 128;
const KNOWN_MACHO_CPU_TYPES: [u32; 7] = [
    7,
    0x0100_0007,
    12,
    0x0100_000c,
    0x0200_000c,
    18,
    0x0100_0012,
];
const MACHO_HEADER_MAGICS: [u32; 4] = [0xfeed_face, 0xfeed_facf, 0xcefa_edfe, 0xcffa_edfe];

fn is_jvm_class_file(bytes: &[u8]) -> bool {
    // 0xCAFEBABE with a plausible class-file minor/major follows the TS helper's
    // intent; the exact minor/major gate is shared with jvmClassFile.ts.
    bytes.len() >= 8 && bytes[..4] == [0xca, 0xfe, 0xba, 0xbe] && {
        let major = u16::from_be_bytes([bytes[6], bytes[7]]);
        major >= 45
    }
}

/// Returns `Some("mach-o-universal")`, `Some("unknown")` or `None` (not FAT).
fn classify_fat_artifact(prefix: &[u8], file_size: u64) -> Option<&'static str> {
    if prefix.len() < 4 {
        return None;
    }
    let magic = u32::from_be_bytes([prefix[0], prefix[1], prefix[2], prefix[3]]);
    if !FAT_MAGICS.contains(&magic) {
        return None;
    }
    if file_size < prefix.len() as u64 {
        return Some("unknown");
    }
    if prefix.len() as u64 == file_size && is_jvm_class_file(prefix) {
        return None;
    }
    if prefix.len() < 8 {
        return if file_size < 8 {
            Some("unknown")
        } else {
            // needs-data: insufficient prefix to decide. TS maps needs-data to
            // "unknown" via classifyFatArtifact only when malformed; needs-data
            // returns "unknown" as well here since the prefix is bounded.
            Some("unknown")
        };
    }
    let little_endian = magic == 0xbeba_feca || magic == 0xbfba_feca;
    let wide = magic == 0xcafe_babf || magic == 0xbfba_feca;
    let count = read_u32(prefix, 4, little_endian);
    if count == 0 {
        return Some("unknown");
    }
    if count > MAX_FAT_ARCHITECTURES {
        return None;
    }
    let entry_size: u64 = if wide { 32 } else { 20 };
    let table_end = 8 + count as u64 * entry_size;
    if table_end > file_size {
        return None;
    }
    if table_end > prefix.len() as u64 {
        return Some("unknown");
    }
    // Decode slices.
    let mut slices = Vec::new();
    for index in 0..count as usize {
        let base = 8 + index * entry_size as usize;
        let cpu_type = read_u32(prefix, base, little_endian);
        let (offset, size) = if wide {
            (
                read_u64(prefix, base + 8, little_endian),
                read_u64(prefix, base + 16, little_endian),
            )
        } else {
            (
                read_u32(prefix, base + 8, little_endian) as u64,
                read_u32(prefix, base + 12, little_endian) as u64,
            )
        };
        let align_exp = read_u32(prefix, base + if wide { 24 } else { 16 }, little_endian);
        slices.push((cpu_type, offset, size, align_exp, index));
    }
    let range_ok = |offset: u64, size: u64, align_exp: u32| -> bool {
        if size == 0 || offset < table_end {
            return false;
        }
        if offset > file_size || size > file_size - offset {
            return false;
        }
        if align_exp > 52 {
            return false;
        }
        offset % (1u64 << align_exp) == 0
    };
    let has_known_cpu = slices
        .iter()
        .any(|(cpu_type, ..)| KNOWN_MACHO_CPU_TYPES.contains(cpu_type));
    let invalid_range = slices
        .iter()
        .any(|(_, offset, size, align_exp, _)| !range_ok(*offset, *size, *align_exp));
    if has_known_cpu {
        return Some(if invalid_range {
            "unknown"
        } else {
            "mach-o-universal"
        });
    }
    // Observe slice headers within the retained prefix.
    let mut observed_macho = false;
    let mut missing = false;
    for (_, offset, size, align_exp, _) in &slices {
        if !range_ok(*offset, *size, *align_exp) {
            continue;
        }
        let off = *offset as usize;
        if off >= prefix.len() {
            missing = true;
        } else if off + 4 <= prefix.len() {
            let magic = u32::from_be_bytes([
                prefix[off],
                prefix[off + 1],
                prefix[off + 2],
                prefix[off + 3],
            ]);
            if MACHO_HEADER_MAGICS.contains(&magic) {
                observed_macho = true;
            }
        } else {
            missing = true;
        }
    }
    if observed_macho {
        return Some(if invalid_range {
            "unknown"
        } else {
            "mach-o-universal"
        });
    }
    if missing {
        return Some("unknown");
    }
    Some("unknown")
}

fn read_u32(bytes: &[u8], offset: usize, little_endian: bool) -> u32 {
    let b = [
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ];
    if little_endian {
        u32::from_le_bytes(b)
    } else {
        u32::from_be_bytes(b)
    }
}

fn read_u64(bytes: &[u8], offset: usize, little_endian: bool) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&bytes[offset..offset + 8]);
    if little_endian {
        u64::from_le_bytes(b)
    } else {
        u64::from_be_bytes(b)
    }
}

// --- bounded XML plist signature (subset of appleArchiveFormat.ts) ---

/// `hasXmlPlistSignature` for a retained prefix. Recognizes an XML prolog that
/// reaches a `<plist` root element or a `<!DOCTYPE ... plist` declaration,
/// skipping comments, processing instructions and whitespace. This is a
/// bounded, signature-only scan; it does not validate the XML document.
pub fn has_xml_plist_signature(bytes: &[u8]) -> bool {
    // Decode a UTF-8/UTF-16 BOM-prefixed text window; fall back to lossy UTF-8.
    let text = decode_prolog_text(bytes);
    xml_plist_prolog_matches(&text)
}

fn decode_prolog_text(bytes: &[u8]) -> String {
    if bytes.len() >= 2 && bytes[0] == 0xff && bytes[1] == 0xfe {
        return decode_utf16(&bytes[2..], true);
    }
    if bytes.len() >= 2 && bytes[0] == 0xfe && bytes[1] == 0xff {
        return decode_utf16(&bytes[2..], false);
    }
    let start = if bytes.len() >= 3 && bytes[0] == 0xef && bytes[1] == 0xbb && bytes[2] == 0xbf {
        3
    } else {
        0
    };
    String::from_utf8_lossy(&bytes[start..]).into_owned()
}

fn decode_utf16(bytes: &[u8], little_endian: bool) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| {
            if little_endian {
                u16::from_le_bytes([c[0], c[1]])
            } else {
                u16::from_be_bytes([c[0], c[1]])
            }
        })
        .collect();
    String::from_utf16_lossy(&units)
}

fn xml_plist_prolog_matches(text: &str) -> bool {
    let chars: Vec<char> = text.chars().collect();
    let mut cursor = 0usize;
    let is_ws = |c: char| c == ' ' || c == '\t' || c == '\r' || c == '\n';
    loop {
        while cursor < chars.len() && is_ws(chars[cursor]) {
            cursor += 1;
        }
        if cursor >= chars.len() {
            return false;
        }
        let rest: String = chars[cursor..].iter().collect();
        if rest.starts_with("<!--") {
            match rest.find("-->") {
                Some(end) => {
                    cursor += rest[..end + 3].chars().count();
                    continue;
                }
                None => return false,
            }
        }
        if rest.starts_with("<?") {
            match rest.find("?>") {
                Some(end) => {
                    cursor += rest[..end + 2].chars().count();
                    continue;
                }
                None => return false,
            }
        }
        if rest.starts_with("<!DOCTYPE") {
            let after = &rest[9..];
            // require whitespace, then a plist name
            let after_trim = after.trim_start();
            return after_trim.starts_with("plist") && {
                let delim = after_trim[5..].chars().next();
                matches!(delim, Some('>') | Some('[')) || delim.map(is_ws).unwrap_or(false)
            };
        }
        if rest.starts_with("<plist") {
            let delim = rest[6..].chars().next();
            return matches!(delim, Some('/') | Some('>')) || delim.map(is_ws).unwrap_or(false);
        }
        return false;
    }
}
