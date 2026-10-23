//! Streaming scanners for Flutter payload libraries inside an APK.
//!
//! Compatibility owner: `src/flutter/FlutterPayloadScan.ts`.
//!
//! All facts are observations of byte patterns at read time: the Dart
//! snapshot hash sits 20 bytes after each snapshot magic, the GNU build-id is
//! an ELF note, and version facts are labeled ASCII strings. Nothing is
//! inferred or looked up externally.

use std::collections::HashSet;

/// Magic starting every Dart VM and isolate snapshot section.
pub const DART_SNAPSHOT_MAGIC: [u8; 4] = [0xf5, 0xf5, 0xdc, 0xdc];
pub const SNAPSHOT_HASH_OFFSET: usize = 20;
pub const SNAPSHOT_HASH_LENGTH: usize = 32;

/// Hard cap on distinct hashes retained before partial coverage reports.
pub const MAX_SNAPSHOT_HASH_CANDIDATES: usize = 64;

/// `SNAPSHOT_HASH_PATTERN` = `^[0-9a-f]{32}$`, over a latin1 candidate slice.
pub fn is_snapshot_hash(candidate: &str) -> bool {
    candidate.len() == SNAPSHOT_HASH_LENGTH
        && candidate
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// First index of `needle` in `haystack` at or after `from`, or `None`.
fn find_bytes(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() {
        return Some(from);
    }
    if haystack.len() < needle.len() {
        return None;
    }
    let last = haystack.len() - needle.len();
    (from..=last).find(|&index| &haystack[index..index + needle.len()] == needle)
}

/// Decode a latin1 byte slice to a Rust `String` (each byte is one code point).
fn latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|&byte| byte as char).collect()
}

/// Result of the Dart snapshot magic/hash scan.
pub struct SnapshotHashScan {
    /// Snapshot sections found.
    pub sources: usize,
    pub capped: bool,
    /// Distinct 32-hex hashes following the magic, in first-seen order.
    pub candidates: Vec<String>,
}

/// Incremental scanner for Dart snapshot magics and the hash that follows.
pub struct SnapshotHashScanner {
    sources: usize,
    capped: bool,
    candidates: Vec<String>,
    candidate_set: HashSet<String>,
    buffer: Vec<u8>,
}

impl SnapshotHashScanner {
    pub fn new() -> Self {
        Self {
            sources: 0,
            capped: false,
            candidates: Vec::new(),
            candidate_set: HashSet::new(),
            buffer: Vec::new(),
        }
    }

    pub fn push(&mut self, chunk: &[u8]) {
        let mut joined = Vec::with_capacity(self.buffer.len() + chunk.len());
        joined.extend_from_slice(&self.buffer);
        joined.extend_from_slice(chunk);
        let mut offset = 0usize;
        let mut pending_magic: Option<usize> = None;
        loop {
            let magic = match find_bytes(&joined, &DART_SNAPSHOT_MAGIC, offset) {
                Some(index) => index,
                None => break,
            };
            if magic + SNAPSHOT_HASH_OFFSET + SNAPSHOT_HASH_LENGTH > joined.len() {
                pending_magic = Some(magic);
                break;
            }
            let candidate = latin1(
                &joined[magic + SNAPSHOT_HASH_OFFSET
                    ..magic + SNAPSHOT_HASH_OFFSET + SNAPSHOT_HASH_LENGTH],
            );
            let is_valid_hash = is_snapshot_hash(&candidate);
            if is_valid_hash && !self.candidate_set.contains(&candidate) {
                if self.candidates.len() == MAX_SNAPSHOT_HASH_CANDIDATES {
                    self.capped = true;
                } else {
                    self.candidate_set.insert(candidate.clone());
                    self.candidates.push(candidate);
                }
            }
            if is_valid_hash {
                self.sources += 1;
            }
            offset = magic + DART_SNAPSHOT_MAGIC.len();
        }
        let keep_from = pending_magic
            .unwrap_or_else(|| joined.len().saturating_sub(DART_SNAPSHOT_MAGIC.len() - 1));
        self.buffer = joined[keep_from..].to_vec();
    }

    pub fn result(&self) -> SnapshotHashScan {
        SnapshotHashScan {
            sources: self.sources,
            candidates: self.candidates.clone(),
            capped: self.capped,
        }
    }
}

/// Labeled strings worth reporting when a build carries them.
pub struct LabeledStringScan {
    pub dart_version: Option<String>,
    pub dart_version_capped: bool,
    pub toolchain_lines: Vec<String>,
    /// True when further distinct matching lines were observed past the cap.
    pub toolchain_capped: bool,
}

const MAX_TOOLCHAIN_LINES: usize = 4;
/// Carry span for either accepted pattern (9 + 80 + 16 + 500 printable bytes).
const CARRY_BYTES: usize = 640;

/// Incremental ASCII string collector that keeps only labeled version and
/// toolchain facts.
pub struct LabeledStringScanner {
    dart_version: Option<String>,
    dart_version_capped: bool,
    toolchain_lines: Vec<String>,
    carry: String,
    overflowed: bool,
    ended: bool,
    toolchain_capped: bool,
}

impl LabeledStringScanner {
    pub fn new() -> Self {
        Self {
            dart_version: None,
            dart_version_capped: false,
            toolchain_lines: Vec::new(),
            carry: String::new(),
            overflowed: false,
            ended: false,
            toolchain_capped: false,
        }
    }

    pub fn push(&mut self, chunk: &[u8]) {
        for &byte in chunk {
            if (0x20..0x7f).contains(&byte) {
                if self.carry.len() < CARRY_BYTES {
                    self.carry.push(byte as char);
                } else {
                    self.overflowed = true;
                }
            } else {
                let text = std::mem::take(&mut self.carry);
                self.consider(&text);
                self.overflowed = false;
            }
        }
    }

    /// Commit any retained tail, e.g. when the stream ends mid-string.
    pub fn end(&mut self) {
        if self.ended {
            return;
        }
        self.ended = true;
        let text = std::mem::take(&mut self.carry);
        self.consider(&text);
        self.overflowed = false;
    }

    fn consider(&mut self, text: &str) {
        if text.starts_with("Dart VM version:") {
            if self.overflowed || !dart_version_matches(text) {
                self.dart_version_capped = true;
            } else if self.dart_version.is_none() {
                self.dart_version = Some(text.to_owned());
            } else if self.dart_version.as_deref() != Some(text) {
                self.dart_version_capped = true;
            }
            return;
        }
        if !text.starts_with("Android (") && !text.starts_with("based on LLVM ") {
            return;
        }
        if self.overflowed || !toolchain_matches(text) {
            self.toolchain_capped = true;
            return;
        }
        let line = text.to_owned();
        if self.toolchain_lines.contains(&line) {
            return;
        }
        if self.toolchain_lines.len() < MAX_TOOLCHAIN_LINES {
            self.toolchain_lines.push(line);
        } else {
            self.toolchain_capped = true;
        }
    }

    pub fn result(&mut self) -> LabeledStringScan {
        if !self.ended {
            self.end();
        }
        LabeledStringScan {
            dart_version: self.dart_version.clone(),
            dart_version_capped: self.dart_version_capped,
            toolchain_lines: self.toolchain_lines.clone(),
            toolchain_capped: self.toolchain_capped,
        }
    }
}

/// `DART_VERSION_PATTERN` = `^Dart VM version:[^\x00\n]{0,200}$`.
///
/// The scanner only feeds printable ASCII runs (0x20..0x7f) terminated by a
/// delimiter, so `\x00` and `\n` never appear in `text`; the body length bound
/// is the only remaining check.
fn dart_version_matches(text: &str) -> bool {
    const PREFIX: &str = "Dart VM version:";
    match text.strip_prefix(PREFIX) {
        Some(rest) => rest.chars().count() <= 200,
        None => false,
    }
}

/// `TOOLCHAIN_PATTERN` =
/// `^(?:Android \([^)\x00\n]{0,80}\) clang version [^\x00\n]{0,500}|based on LLVM \d[^\x00\n]{0,80})$`.
fn toolchain_matches(text: &str) -> bool {
    android_clang_matches(text) || based_on_llvm_matches(text)
}

fn android_clang_matches(text: &str) -> bool {
    let rest = match text.strip_prefix("Android (") {
        Some(rest) => rest,
        None => return false,
    };
    // `[^)\x00\n]{0,80}` then a literal `)`.
    let mut group = String::new();
    let mut chars = rest.char_indices();
    let mut close_at: Option<usize> = None;
    for (index, ch) in chars.by_ref() {
        if ch == ')' {
            close_at = Some(index);
            break;
        }
        group.push(ch);
    }
    let close_at = match close_at {
        Some(index) => index,
        None => return false,
    };
    if group.chars().count() > 80 {
        return false;
    }
    let after = &rest[close_at + ')'.len_utf8()..];
    let tail = match after.strip_prefix(" clang version ") {
        Some(tail) => tail,
        None => return false,
    };
    tail.chars().count() <= 500
}

fn based_on_llvm_matches(text: &str) -> bool {
    let rest = match text.strip_prefix("based on LLVM ") {
        Some(rest) => rest,
        None => return false,
    };
    // `\d` then `[^\x00\n]{0,80}`.
    let mut chars = rest.chars();
    match chars.next() {
        Some(first) if first.is_ascii_digit() => {}
        _ => return false,
    }
    chars.count() <= 80
}
