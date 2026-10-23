// Textual compatibility shared by the stat and status owners. This preserves
// existing caller semantics; it is not a generic Unicode or numeric coercion API.
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

pub(crate) fn decimal(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
}

pub(crate) fn safe_decimal(value: &str) -> Option<u64> {
    if value.is_empty() {
        return None;
    }
    value.bytes().try_fold(0_u64, |number, byte| {
        if !byte.is_ascii_digit() {
            return None;
        }
        number
            .checked_mul(10)?
            .checked_add(u64::from(byte - b'0'))
            .filter(|number| *number <= MAX_SAFE_INTEGER)
    })
}

// Match ECMAScript trim/\s, not Rust's different Unicode White_Space set
// (notably U+0085 versus U+FEFF).
pub(crate) fn contract_whitespace(character: char) -> bool {
    matches!(character,
        '\u{0009}'..='\u{000d}' | ' ' | '\u{00a0}' | '\u{1680}' |
        '\u{2000}'..='\u{200a}' | '\u{2028}' | '\u{2029}' |
        '\u{202f}' | '\u{205f}' | '\u{3000}' | '\u{feff}')
}
