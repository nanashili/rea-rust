//! Port of `src/native/parsers/echoedPath.ts`.

use regex::Regex;
use std::sync::OnceLock;

/// Remove the header line otool and dyld_info print before a slice's output:
/// `<path>:`, `<path> (architecture <arch>):`, or `<path> [<arch>]:`. File
/// names may contain line breaks and tool keywords, so only the exact operand
/// path is stripped; output without that header is returned unchanged.
pub(crate) fn without_echoed_path_header(output: &str, path: Option<&str>) -> String {
    let Some(path) = path else {
        return output.to_owned();
    };
    let Some(rest) = output.strip_prefix(path) else {
        return output.to_owned();
    };
    // Anchored match at the start of the remainder, exactly like the `^` regex.
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r"^(?: \(architecture [^)\n]*\)| \[[^\]\n]*\])?:\r?\n").expect("valid")
    });
    match re.find(rest) {
        None => output.to_owned(),
        Some(matched) => {
            debug_assert_eq!(matched.start(), 0);
            rest[matched.end()..].to_owned()
        }
    }
}
