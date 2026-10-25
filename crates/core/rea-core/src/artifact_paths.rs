//! Shared normalization for slash-separated artifact logical paths.

use std::fmt;
use unicode_normalization::UnicodeNormalization;

use crate::JsString;

/// The reason an artifact logical path could not be normalized safely.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArtifactPathError {
    /// The path contains a NUL byte, is absolute, or has an ASCII drive prefix.
    AbsoluteOrUnsafe(String),
    /// The path contains an empty, current-directory, or parent-directory component.
    NotNormalized(String),
}

impl fmt::Display for ArtifactPathError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AbsoluteOrUnsafe(input) => write!(
                formatter,
                "Artifact path is absolute or unsafe: {}",
                serde_json::to_string(input).expect("strings serialize")
            ),
            Self::NotNormalized(input) => write!(
                formatter,
                "Artifact path is not normalized: {}",
                serde_json::to_string(input).expect("strings serialize")
            ),
        }
    }
}

impl std::error::Error for ArtifactPathError {}

/// Normalize one slash-separated logical artifact path into canonical NFC.
///
/// Backslashes remain literal path components, matching the TypeScript
/// `normalizeArtifactPath` contract rather than host filesystem semantics.
pub fn normalize_artifact_path(input: &str) -> Result<String, ArtifactPathError> {
    if input.contains('\0') || input.starts_with('/') || is_drive_prefixed(input) {
        return Err(ArtifactPathError::AbsoluteOrUnsafe(input.to_owned()));
    }

    let normalized = input.nfc().collect::<String>();
    let normalized = normalized.trim_end_matches('/').to_owned();
    let has_unsafe_component = normalized
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == "..");
    if normalized.is_empty() || has_unsafe_component {
        return Err(ArtifactPathError::NotNormalized(input.to_owned()));
    }

    Ok(normalized)
}

/// Normalize a logical artifact path without decoding its UTF-16 units.
pub fn normalize_artifact_js_path(input: &JsString) -> Result<JsString, ArtifactPathError> {
    let mut units = input.units().to_vec();
    while units.last() == Some(&u16::from(b'/')) {
        units.pop();
    }

    let has_unsafe_component = units.split(|unit| *unit == u16::from(b'/')).any(|part| {
        part.is_empty() || part == [u16::from(b'.')] || part == [u16::from(b'.'), u16::from(b'.')]
    });
    let drive_prefixed = units.len() >= 2
        && units[0] <= 0x7f
        && (units[0] as u8).is_ascii_alphabetic()
        && units[1] == u16::from(b':');
    if units.is_empty()
        || units[0] == u16::from(b'/')
        || units.iter().any(|unit| *unit == 0)
        || drive_prefixed
        || has_unsafe_component
    {
        return Err(ArtifactPathError::NotNormalized(input.to_string()));
    }

    let normalized = normalize_utf16_nfc(&units);
    if let Some(text) = normalized.as_str() {
        return normalize_artifact_path(text).map(JsString::from);
    }
    Ok(normalized)
}

fn normalize_utf16_nfc(units: &[u16]) -> JsString {
    let mut normalized = Vec::with_capacity(units.len());
    let mut scalar_run = String::new();

    for decoded in std::char::decode_utf16(units.iter().copied()) {
        match decoded {
            Ok(character) => scalar_run.push(character),
            Err(error) => {
                append_nfc_units(&mut normalized, &scalar_run);
                scalar_run.clear();
                normalized.push(error.unpaired_surrogate());
            }
        }
    }
    append_nfc_units(&mut normalized, &scalar_run);

    JsString::from_utf16(normalized)
}

fn append_nfc_units(output: &mut Vec<u16>, scalar_run: &str) {
    let normalized = scalar_run.nfc().collect::<String>();
    output.extend(normalized.encode_utf16());
}

fn is_drive_prefixed(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

#[cfg(test)]
mod tests {
    use super::{ArtifactPathError, normalize_artifact_js_path, normalize_artifact_path};
    use crate::JsString;

    #[test]
    fn normalizes_nfc_and_preserves_backslashes() {
        assert_eq!(
            normalize_artifact_path("e\u{301}\\bundle.js/").unwrap(),
            "é\\bundle.js"
        );
    }

    #[test]
    fn rejects_absolute_drive_and_traversal_paths() {
        for input in [
            "/bundle.js",
            "C:/bundle.js",
            "bundle/../main.js",
            "bundle//main.js",
        ] {
            assert!(matches!(
                normalize_artifact_path(input),
                Err(ArtifactPathError::AbsoluteOrUnsafe(_))
                    | Err(ArtifactPathError::NotNormalized(_))
            ));
        }
    }

    #[test]
    fn javascript_paths_trim_trailing_slashes_before_component_validation() {
        assert_eq!(
            normalize_artifact_js_path(&JsString::from("bundle.js/")).unwrap(),
            JsString::from("bundle.js")
        );
    }

    #[test]
    fn javascript_paths_normalize_scalar_runs_around_unpaired_surrogates() {
        let input = JsString::from_utf16([b'e' as u16, 0x0301, 0xd800, b'e' as u16, 0x0301]);
        assert_eq!(
            normalize_artifact_js_path(&input).unwrap(),
            JsString::from_utf16([0x00e9, 0xd800, 0x00e9])
        );
    }
}
