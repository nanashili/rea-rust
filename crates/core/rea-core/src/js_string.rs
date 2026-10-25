//! Lossless JavaScript strings represented by UTF-16 code units.

use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::sync::OnceLock;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::JsonText;

/// An ECMAScript string represented by its UTF-16 code units.
///
/// Rust strings cannot represent an unpaired surrogate. Keeping the units at
/// this boundary preserves JavaScript source values through interpolation,
/// equality, budgeting, and JSON serialization.
#[derive(Clone, Debug)]
pub struct JsString {
    storage: Option<Arc<JsStringStorage>>,
}

#[derive(Debug)]
struct JsStringStorage {
    source: JsStringSource,
    units: OnceLock<Vec<u16>>,
    unit_len: OnceLock<usize>,
    valid_utf8: OnceLock<Option<String>>,
}

#[derive(Debug)]
enum JsStringSource {
    Utf16(Vec<u16>),
    Utf8(String),
}

impl Default for JsString {
    fn default() -> Self {
        Self::new_const()
    }
}

impl PartialEq for JsString {
    fn eq(&self, other: &Self) -> bool {
        self.units() == other.units()
    }
}

impl Eq for JsString {}

impl Hash for JsString {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.units().hash(state);
    }
}

impl PartialOrd for JsString {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for JsString {
    fn cmp(&self, other: &Self) -> Ordering {
        self.units().cmp(other.units())
    }
}

impl JsString {
    /// Construct an empty JavaScript string in a `const` context.
    pub const fn new_const() -> Self {
        Self { storage: None }
    }

    /// Construct a JavaScript string from exact UTF-16 code units.
    pub fn from_utf16(units: impl Into<Vec<u16>>) -> Self {
        let units = units.into();
        if units.is_empty() {
            Self::new_const()
        } else {
            Self {
                storage: Some(Arc::new(JsStringStorage {
                    source: JsStringSource::Utf16(units),
                    units: OnceLock::new(),
                    unit_len: OnceLock::new(),
                    valid_utf8: OnceLock::new(),
                })),
            }
        }
    }

    /// Borrow the exact UTF-16 code units.
    pub fn units(&self) -> &[u16] {
        let Some(storage) = self.storage.as_deref() else {
            return &[];
        };

        match &storage.source {
            JsStringSource::Utf16(units) => units,
            JsStringSource::Utf8(text) => {
                storage.units.get_or_init(|| text.encode_utf16().collect())
            }
        }
    }

    /// Return whether the string contains no UTF-16 code units.
    pub fn is_empty(&self) -> bool {
        self.storage
            .as_deref()
            .is_none_or(|storage| match &storage.source {
                JsStringSource::Utf16(units) => units.is_empty(),
                JsStringSource::Utf8(value) => value.is_empty(),
            })
    }

    /// Return the number of UTF-16 code units in the string.
    pub fn len(&self) -> usize {
        let Some(storage) = self.storage.as_deref() else {
            return 0;
        };

        *storage.unit_len.get_or_init(|| match &storage.source {
            JsStringSource::Utf16(units) => units.len(),
            JsStringSource::Utf8(text) => text.encode_utf16().count(),
        })
    }

    /// Iterate over the exact UTF-16 code units.
    pub fn encode_utf16(&self) -> impl Iterator<Item = u16> + '_ {
        let storage = self.storage.as_deref();
        let mut utf8 = None;
        let mut index = 0;

        std::iter::from_fn(move || {
            let Some(storage) = storage else {
                return None;
            };

            match &storage.source {
                JsStringSource::Utf16(units) => {
                    let unit = units.get(index).copied();
                    if unit.is_some() {
                        index += 1;
                    }
                    unit
                }
                JsStringSource::Utf8(text) => {
                    utf8.get_or_insert_with(|| text.encode_utf16()).next()
                }
            }
        })
    }

    /// Append another JavaScript string without replacing unpaired surrogates.
    pub fn extend(&mut self, other: &Self) {
        if other.is_empty() {
            return;
        }

        if let (Some(left), Some(right)) = (self.source_str(), other.source_str()) {
            let mut combined = String::with_capacity(left.len() + right.len());
            combined.push_str(left);
            combined.push_str(right);
            *self = Self::from(combined);
            return;
        }

        let mut units = Vec::with_capacity(self.len() + other.len());
        units.extend_from_slice(self.units());
        units.extend_from_slice(other.units());
        *self = Self::from_utf16(units);
    }

    /// Return the concatenation of two JavaScript strings.
    pub fn concat(&self, other: &Self) -> Self {
        if let (Some(left), Some(right)) = (self.source_str(), other.source_str()) {
            let mut combined = String::with_capacity(left.len() + right.len());
            combined.push_str(left);
            combined.push_str(right);
            return Self::from(combined);
        }

        let mut units = Vec::with_capacity(self.len() + other.len());
        units.extend_from_slice(self.units());
        units.extend_from_slice(other.units());
        Self::from_utf16(units)
    }

    /// Return this string with ordinary UTF-8 text prepended.
    ///
    /// Building the final representation directly avoids creating a separate
    /// owned copy of `self` before concatenation. The UTF-16 branch remains
    /// exact for strings containing unpaired surrogates.
    pub fn prefixed(&self, prefix: &str) -> Self {
        if let Some(value) = self.source_str() {
            let mut combined = String::with_capacity(prefix.len() + value.len());
            combined.push_str(prefix);
            combined.push_str(value);
            return Self::from(combined);
        }

        let prefix_units = prefix.encode_utf16().count();
        let mut units = Vec::with_capacity(prefix_units + self.len());
        units.extend(prefix.encode_utf16());
        units.extend_from_slice(self.units());
        Self::from_utf16(units)
    }

    /// Return this string followed by ordinary UTF-8 text.
    pub fn concat_str(&self, other: &str) -> Self {
        self.concat(&Self::from(other))
    }

    /// Join JavaScript strings with an ordinary UTF-8 separator.
    pub fn join<I>(parts: I, separator: &str) -> Self
    where
        I: IntoIterator<Item = Self>,
    {
        let mut result = Self::from("");
        let separator = Self::from(separator);
        let mut first = true;

        for part in parts {
            if !first {
                result.extend(&separator);
            }

            result.extend(&part);
            first = false;
        }

        result
    }

    /// Decode only when every UTF-16 code unit belongs to a Unicode scalar value.
    pub fn try_to_string(&self) -> Result<String, std::string::FromUtf16Error> {
        let Some(storage) = self.storage.as_deref() else {
            return Ok(String::new());
        };

        match &storage.source {
            JsStringSource::Utf8(value) => Ok(value.clone()),
            JsStringSource::Utf16(units) => match storage
                .valid_utf8
                .get_or_init(|| String::from_utf16(units).ok())
            {
                Some(value) => Ok(value.clone()),
                None => String::from_utf16(units),
            },
        }
    }

    /// Borrow the UTF-8 view when all units are Unicode scalar values.
    pub fn as_str(&self) -> Option<&str> {
        let Some(storage) = self.storage.as_deref() else {
            return Some("");
        };

        match &storage.source {
            JsStringSource::Utf8(value) => Some(value),
            JsStringSource::Utf16(units) => storage
                .valid_utf8
                .get_or_init(|| String::from_utf16(units).ok())
                .as_deref(),
        }
    }

    fn source_str(&self) -> Option<&str> {
        let Some(storage) = self.storage.as_deref() else {
            return Some("");
        };

        match &storage.source {
            JsStringSource::Utf8(value) => Some(value),
            JsStringSource::Utf16(_) => None,
        }
    }

    /// Decode UTF-16 units into JavaScript code points for ordering.
    pub fn code_points(&self) -> impl Iterator<Item = u32> + '_ {
        std::char::decode_utf16(self.units().iter().copied()).map(|result| {
            result
                .map(u32::from)
                .unwrap_or_else(|error| u32::from(error.unpaired_surrogate()))
        })
    }

    /// Compare strings by decoded Unicode code points rather than UTF-16 units.
    pub fn compare_code_points(&self, other: &Self) -> Ordering {
        self.code_points().cmp(other.code_points())
    }

    /// Return whether this string begins with the exact UTF-16 units in `prefix`.
    pub fn starts_with(&self, prefix: &Self) -> bool {
        self.units().starts_with(prefix.units())
    }

    /// Remove an exact UTF-16 prefix when it is present.
    pub fn strip_prefix(&self, prefix: &str) -> Option<Self> {
        let prefix_units: Vec<u16> = prefix.encode_utf16().collect();
        self.units()
            .starts_with(&prefix_units)
            .then(|| Self::from_utf16(self.units()[prefix_units.len()..].to_vec()))
    }

    /// Return whether the string ends with the exact UTF-16 encoding of text.
    pub fn ends_with(&self, suffix: &str) -> bool {
        let suffix_units: Vec<u16> = suffix.encode_utf16().collect();
        self.units().ends_with(&suffix_units)
    }

    /// Remove an exact UTF-16 suffix when it is present.
    pub fn strip_suffix(&self, suffix: &str) -> Option<Self> {
        let suffix_units: Vec<u16> = suffix.encode_utf16().collect();
        self.units()
            .ends_with(&suffix_units)
            .then(|| Self::from_utf16(self.units()[..self.len() - suffix_units.len()].to_vec()))
    }

    /// Return the path component count using the logical slash separator.
    pub fn component_count(&self) -> usize {
        self.units().split(|unit| *unit == u16::from(b'/')).count()
    }

    /// Return the UTF-16 slice corresponding to a range of code units.
    pub fn slice_units(&self, range: std::ops::Range<usize>) -> Self {
        Self::from_utf16(self.units()[range].to_vec())
    }

    /// Lowercase ASCII letters while preserving every other UTF-16 code unit.
    pub fn to_ascii_lowercase(&self) -> Self {
        Self::from_utf16(
            self.units()
                .iter()
                .map(|unit| {
                    if (u16::from(b'A')..=u16::from(b'Z')).contains(unit) {
                        *unit + (u16::from(b'a') - u16::from(b'A'))
                    } else {
                        *unit
                    }
                })
                .collect::<Vec<u16>>(),
        )
    }
}

impl From<&str> for JsString {
    fn from(value: &str) -> Self {
        Self::from(value.to_owned())
    }
}

impl From<String> for JsString {
    fn from(value: String) -> Self {
        if value.is_empty() {
            return Self::new_const();
        }

        Self {
            storage: Some(Arc::new(JsStringStorage {
                source: JsStringSource::Utf8(value),
                units: OnceLock::new(),
                unit_len: OnceLock::new(),
                valid_utf8: OnceLock::new(),
            })),
        }
    }
}

impl From<&String> for JsString {
    fn from(value: &String) -> Self {
        Self::from(value.as_str())
    }
}

impl From<&JsString> for JsString {
    fn from(value: &JsString) -> Self {
        value.clone()
    }
}

impl fmt::Display for JsString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(value) = self.as_str() {
            return formatter.write_str(value);
        }

        for unit in self.units() {
            write!(formatter, "\\u{unit:04x}")?;
        }
        Ok(())
    }
}

impl PartialEq<str> for JsString {
    fn eq(&self, other: &str) -> bool {
        self.encode_utf16().eq(other.encode_utf16())
    }
}

impl PartialEq<&str> for JsString {
    fn eq(&self, other: &&str) -> bool {
        self == *other
    }
}

impl PartialEq<&JsString> for JsString {
    fn eq(&self, other: &&JsString) -> bool {
        self == *other
    }
}

impl PartialEq<String> for JsString {
    fn eq(&self, other: &String) -> bool {
        self == other.as_str()
    }
}

impl PartialEq<JsString> for String {
    fn eq(&self, other: &JsString) -> bool {
        other == self
    }
}

impl Serialize for JsString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if let Some(value) = self.as_str() {
            return serializer.serialize_str(value);
        }

        let text = JsonText::from_utf16_units(self.units()).map_err(serde::ser::Error::custom)?;
        text.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for JsString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let text = JsonText::deserialize(deserializer).map_err(serde::de::Error::custom)?;
        match text
            .into_string_or_units()
            .map_err(serde::de::Error::custom)?
        {
            Ok(value) => Ok(Self::from(value)),
            Err(units) => Ok(Self::from_utf16(units)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{JsString, JsStringSource};
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    #[test]
    fn empty_const_matches_empty_text_for_value_semantics() {
        let constant = JsString::new_const();
        let text = JsString::from("");

        assert_eq!(constant, text);
        assert_eq!(constant.hash_value(), text.hash_value());
        assert_eq!(constant.cmp(&text), std::cmp::Ordering::Equal);
        assert_eq!(constant.try_to_string().expect("empty decodes"), "");
    }

    #[test]
    fn cloning_shares_storage_until_extend_mutates_the_clone() {
        let original = JsString::from_utf16(vec![b'a' as u16, 0xd800]);
        let mut clone = original.clone();

        clone.extend(&JsString::from("b"));

        assert_eq!(original.units(), &[b'a' as u16, 0xd800]);
        assert_eq!(clone.units(), &[b'a' as u16, 0xd800, b'b' as u16]);
        assert_eq!(original.as_str(), None);
        assert_eq!(clone.as_str(), None);
    }

    #[test]
    fn ordinary_text_keeps_utf8_without_materializing_utf16() {
        let text = JsString::from("large source text 🚀");
        let storage = text.storage.as_deref().expect("non-empty text has storage");

        assert!(matches!(&storage.source, JsStringSource::Utf8(_)));
        assert!(storage.units.get().is_none());
        assert_eq!(text.len(), text.encode_utf16().count());
        assert!(storage.units.get().is_none());
        assert_eq!(
            text.encode_utf16().collect::<Vec<_>>(),
            "large source text 🚀".encode_utf16().collect::<Vec<_>>()
        );
        assert!(storage.units.get().is_none());
        assert_eq!(
            serde_json::to_string(&text).expect("serializes"),
            "\"large source text 🚀\""
        );
        assert!(storage.units.get().is_none());
    }

    #[test]
    fn prefixed_preserves_unpaired_surrogates() {
        let value = JsString::from_utf16([0xd800, b'x' as u16]);

        assert_eq!(
            value.prefixed("string:").units(),
            &[
                b's' as u16,
                b't' as u16,
                b'r' as u16,
                b'i' as u16,
                b'n' as u16,
                b'g' as u16,
                b':' as u16,
                0xd800,
                b'x' as u16,
            ]
        );
    }

    #[test]
    fn utf16_and_unpaired_serialization_remain_exact() {
        let paired = JsString::from_utf16([0xd83d, 0xde80]);
        let unpaired = JsString::from_utf16([b'a' as u16, 0xd800, b'b' as u16]);

        assert_eq!(
            serde_json::to_string(&paired).expect("serializes"),
            "\"🚀\""
        );
        assert_eq!(
            serde_json::to_string(&unpaired).expect("serializes"),
            "\"a\\ud800b\""
        );
        assert_eq!(unpaired.units(), &[b'a' as u16, 0xd800, b'b' as u16]);
        assert_eq!(unpaired.as_str(), None);
    }

    #[test]
    fn lazy_and_exact_sources_have_identical_value_semantics() {
        let text = "café 🚀";
        let from_utf8 = JsString::from(text);
        let from_utf16 = JsString::from_utf16(text.encode_utf16().collect::<Vec<_>>());

        assert_eq!(from_utf8, from_utf16);
        assert_eq!(from_utf8.hash_value(), from_utf16.hash_value());
        assert_eq!(from_utf8.cmp(&from_utf16), std::cmp::Ordering::Equal);
        assert_eq!(
            from_utf8.code_points().collect::<Vec<_>>(),
            from_utf16.code_points().collect::<Vec<_>>()
        );
    }

    #[test]
    fn deserialization_keeps_unicode_text_owned_as_utf8() {
        let text: JsString = serde_json::from_str(r#""café 🚀""#).expect("valid JSON text");
        let storage = text.storage.as_deref().expect("non-empty text has storage");

        assert!(matches!(&storage.source, JsStringSource::Utf8(_)));
        assert!(storage.units.get().is_none());
        assert_eq!(text, "café 🚀");
    }

    #[test]
    fn deserialization_preserves_escaped_surrogates_exactly() {
        let paired: JsString = serde_json::from_str(r#""\ud83d\ude80""#).expect("valid pair");
        let unpaired: JsString = serde_json::from_str(r#""a\ud800b""#).expect("valid escape");

        assert_eq!(paired, JsString::from("🚀"));
        assert_eq!(unpaired.units(), &[b'a' as u16, 0xd800, b'b' as u16]);
        assert_eq!(unpaired.as_str(), None);
    }

    trait HashValue {
        fn hash_value(&self) -> u64;
    }

    impl HashValue for JsString {
        fn hash_value(&self) -> u64 {
            let mut hasher = DefaultHasher::new();
            self.hash(&mut hasher);
            hasher.finish()
        }
    }
}
