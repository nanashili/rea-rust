//! NUL-framed directory listing parser.
//!
//! Compatibility owner: `src/adb/AdbDirectoryListing.ts`.
use std::sync::OnceLock;

/// One directory entry.
#[derive(Clone, Debug)]
pub struct AdbDirectoryEntry {
    pub name: String,
    pub kind: &'static str,
    pub permissions: Option<String>,
    pub owner: Option<String>,
    pub group: Option<String>,
    pub bytes: Option<i64>,
    pub date: Option<String>,
    pub link_target: Option<String>,
}

/// The remote batch script run through `adb shell`.
pub const ADB_DIRECTORY_BATCH_SCRIPT: &str = "metadata=$(stat -c '%A|%U|%G|%s|%y' \"$@\") || exit\nprintf '%s\\n' \"$metadata\" | {\n  while IFS= read -r metadata; do\n    [ \"$#\" -gt 0 ] || exit 1\n    path=$1\n    shift\n    printf '%s\\000%s\\000' \"$metadata\" \"${path##*/}\"\n    case \"$metadata\" in\n      l*) readlink -n \"$path\" || exit 1 ;;\n    esac\n    printf '\\000'\n  done\n  [ \"$#\" -eq 0 ]\n}";

fn metadata_regex() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r"^([bcdlps-][rwxstST-]{9})\|([^|\n]+)\|([^|\n]+)\|(\d+)\|([^|\n]+)$")
            .unwrap()
    })
}

fn is_safe_integer(value: f64) -> bool {
    value.fract() == 0.0 && value.abs() <= 9_007_199_254_740_991.0
}

fn parse_entry(metadata: &str, name: &str, link_target: &str) -> Option<AdbDirectoryEntry> {
    let captures = metadata_regex().captures(metadata)?;
    if name.is_empty() || name.contains('/') {
        return None;
    }
    let permissions = captures[1].to_owned();
    let bytes_value: f64 = captures[4].parse().ok()?;
    if !is_safe_integer(bytes_value) {
        return None;
    }
    let is_symlink = permissions.starts_with('l');
    if is_symlink == link_target.is_empty() {
        // symlink must have a target; non-symlink must have none.
        return None;
    }
    let kind = if permissions.starts_with('d') {
        "directory"
    } else if is_symlink {
        "symlink"
    } else if permissions.starts_with('-') {
        "file"
    } else {
        "other"
    };
    Some(AdbDirectoryEntry {
        name: name.to_owned(),
        kind,
        permissions: Some(permissions),
        owner: Some(captures[2].to_owned()),
        group: Some(captures[3].to_owned()),
        bytes: Some(bytes_value as i64),
        date: Some(captures[5].to_owned()),
        link_target: if is_symlink {
            Some(link_target.to_owned())
        } else {
            None
        },
    })
}

/// Parsed directory listing.
pub struct DirectoryListing {
    pub entries: Vec<AdbDirectoryEntry>,
    pub unparsed_lines: Vec<String>,
}

fn describe_unparsed(record: &[u8]) -> String {
    match std::str::from_utf8(record) {
        Ok(text) => text.to_owned(),
        Err(_) => format!("Invalid UTF-8 directory record (hex): {}", to_hex(record)),
    }
}

fn to_hex(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push_str(&format!("{byte:02x}"));
    }
    result
}

/// `parseAdbDirectoryListing(stdout)`.
pub fn parse_adb_directory_listing(stdout: &[u8]) -> DirectoryListing {
    let mut entries = Vec::new();
    let mut unparsed_lines = Vec::new();
    let mut offset = 0usize;
    while offset < stdout.len() {
        let metadata_end = find_nul(stdout, offset);
        let name_end = metadata_end.and_then(|index| find_nul(stdout, index + 1));
        let target_end = name_end.and_then(|index| find_nul(stdout, index + 1));
        let Some(target_end) = target_end else {
            unparsed_lines.push(describe_unparsed(&stdout[offset..]));
            break;
        };
        let metadata_end = metadata_end.unwrap();
        let name_end = name_end.unwrap();
        let raw_record = &stdout[offset..target_end + 1];
        if std::str::from_utf8(raw_record).is_err() {
            unparsed_lines.push(describe_unparsed(raw_record));
        } else {
            let metadata = std::str::from_utf8(&stdout[offset..metadata_end]).unwrap_or_default();
            let name = std::str::from_utf8(&stdout[metadata_end + 1..name_end]).unwrap_or_default();
            let target = std::str::from_utf8(&stdout[name_end + 1..target_end]).unwrap_or_default();
            match parse_entry(metadata, name, target) {
                Some(entry) => entries.push(entry),
                None => unparsed_lines.push(String::from_utf8_lossy(raw_record).into_owned()),
            }
        }
        offset = target_end + 1;
    }
    DirectoryListing {
        entries,
        unparsed_lines,
    }
}

fn find_nul(bytes: &[u8], start: usize) -> Option<usize> {
    bytes[start..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| p + start)
}
