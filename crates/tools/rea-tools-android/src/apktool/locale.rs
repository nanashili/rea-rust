//! Android resource-table locale classification and request refinements.
//!
//! Compatibility owner: `src/domain/apktool/apktoolResourceAnalysis.ts`.
//! The locale pattern itself is enforced by the frozen input schema; this
//! module ports the Zod refinement that rejects non-locale configuration
//! qualifiers, the admitted-alias to directory-suffix normalization, and the
//! exact classification of a decoded `res/values-<suffix>/strings.xml` table.

use std::sync::OnceLock;

/// Android resource configuration qualifiers that look like locales but are not.
const NON_LOCALE_QUALIFIERS: [&str; 8] = [
    "car",
    "desk",
    "television",
    "appliance",
    "watch",
    "vrheadset",
    "night",
    "notnight",
];

/// `!ANDROID_NON_LOCALE_QUALIFIERS.has(value.toLowerCase())`.
pub fn is_locale_qualifier(value: &str) -> bool {
    let lowered = value.to_lowercase();
    !NON_LOCALE_QUALIFIERS.contains(&lowered.as_str())
}

fn region_alias_regex() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"^([a-z]{2,3})-([A-Z]{2})$").unwrap())
}

fn numeric_alias_regex() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"^([a-z]{2,3})-([0-9]{3})$").unwrap())
}

/// `androidLocaleDirectorySuffix(locale)`: normalize an admitted request alias
/// to the directory suffix Apktool emits.
pub fn directory_suffix(locale: &str) -> String {
    if let Some(caps) = region_alias_regex().captures(locale) {
        return format!("{}-r{}", &caps[1], &caps[2]);
    }
    if let Some(caps) = numeric_alias_regex().captures(locale) {
        return format!("b+{}+{}", &caps[1], &caps[2]);
    }
    locale.to_owned()
}

/// A classified decoded strings-table suffix.
pub enum TableClass {
    /// A selectable locale table named by its admitted alias.
    Locale(String),
    /// Another resource configuration whose suffix is preserved by its owner.
    Other,
}

fn qualifier_regex() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(
            r"^(?:[a-z]{2,3}(?:-(?:r?[A-Z]{2}|[0-9]{3}))?|b\+[a-z]{2,3}(?:\+[A-Za-z0-9]{2,8})*)$",
        )
        .unwrap()
    })
}

const MAX_SUFFIX_LENGTH: usize = 2 + 3 + (1 + 4) + (1 + 3) + (1 + 8);

/// `classifyAndroidStringsTable(suffix)`.
pub fn classify_strings_table(suffix: &str) -> TableClass {
    let admitted = suffix.len() >= 2
        && suffix.len() <= MAX_SUFFIX_LENGTH
        && qualifier_regex().is_match(suffix)
        && is_locale_qualifier(suffix);
    if admitted && directory_suffix(suffix) == suffix {
        TableClass::Locale(suffix.to_owned())
    } else {
        TableClass::Other
    }
}
