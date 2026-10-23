//! Swift symbol recognition and literal nominal-category decoding.
//!
//! Compatibility owner: `domain/swiftSymbolClassification.ts`. Offsets and
//! lengths are JavaScript UTF-16 code units.

/// A decoded procedure category, or `None` when the mangling is Swift but
/// its nominal category is not decoded.
pub type Category = Option<&'static str>;

const LEGACY_CATEGORIES: [(&str, &str); 5] = [
    ("_TtC", "classes"),
    ("_TtV", "structs"),
    ("_TtO", "enums"),
    ("_TtP", "protocols"),
    ("_TtE", "extensions"),
];

fn nominal(kind: u16) -> Option<&'static str> {
    match kind {
        0x43 => Some("classes"),   // C
        0x56 => Some("structs"),   // V
        0x4f => Some("enums"),     // O
        0x50 => Some("protocols"), // P
        _ => None,
    }
}

fn is_identifier(units: &[u16]) -> bool {
    let Some((first, rest)) = units.split_first() else {
        return false;
    };
    let alpha = |unit: u16| matches!(unit, 0x41..=0x5a | 0x61..=0x7a | 0x5f);
    alpha(*first)
        && rest
            .iter()
            .all(|unit| alpha(*unit) || matches!(unit, 0x30..=0x39))
}

/// `identifierEnd`: end of one length-prefixed literal identifier.
fn identifier_end(mangling: &[u16], offset: usize) -> Option<usize> {
    let rest = mangling.get(offset..)?;
    if !rest.first().is_some_and(|unit| matches!(unit, 0x31..=0x39)) {
        return None;
    }
    let digits = rest
        .iter()
        .take_while(|unit| matches!(unit, 0x30..=0x39))
        .count();
    let token = String::from_utf16_lossy(&rest[..digits]);
    let length = token.parse::<u64>().ok()?;
    let start = offset + digits;
    let end = (start as u64).checked_add(length)?;
    if end > mangling.len() as u64 {
        return None;
    }
    let end = end as usize;
    is_identifier(&mangling[start..end]).then_some(end)
}

/// `classifySwiftSymbol`: `None` when the name is not a recognized Swift
/// symbol; `Some(category)` otherwise.
pub fn classify(name: &str) -> Option<Category> {
    let prefix = ["_$s", "_$S", "$s", "$S", "__T0", "_T0"]
        .into_iter()
        .find(|prefix| name.starts_with(prefix));
    let Some(prefix) = prefix else {
        if !name.contains("_Tt") {
            return None;
        }
        return Some(
            LEGACY_CATEGORIES
                .iter()
                .find(|(prefix, _)| name.starts_with(prefix))
                .map(|(_, category)| *category),
        );
    };
    let mangling = name[prefix.len()..].encode_utf16().collect::<Vec<_>>();
    let Some(mut offset) = identifier_end(&mangling, 0) else {
        return Some(None);
    };
    let mut category: Category = None;
    while let Some(end) = identifier_end(&mangling, offset) {
        let kind = mangling.get(end).copied();
        match kind.and_then(nominal) {
            Some(decoded) => {
                category = Some(decoded);
                offset = end + 1;
            }
            None => {
                if mangling[end..] == [0x4d, 0x70] {
                    category = Some("protocols");
                } else if kind == Some(0x45) && category.is_some() {
                    category = Some("extensions");
                }
                break;
            }
        }
    }
    Some(category)
}

/// `isSwiftMangledSymbolName`: prefixes the Swift demangler accepts.
pub fn is_mangled_symbol_name(name: &str) -> bool {
    [
        "_T0",
        "$S",
        "_$S",
        "$s",
        "_$s",
        "@__swiftmacro_",
        "$e",
        "_$e",
    ]
    .into_iter()
    .any(|prefix| name.starts_with(prefix))
}

/// `isSwiftSymbolName` (`symbolAnalysis.ts`).
pub fn is_symbol_name(name: &str) -> bool {
    is_mangled_symbol_name(name) || classify(name).is_some()
}
