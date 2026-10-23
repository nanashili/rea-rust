//! Caller-selected headerless load admission.
//!
//! Ports `src/domain/rawBinary.ts` (`admitRawBinary`, `rawBinarySelectionError`,
//! `validateRawBinaryLength`, `parseRawBinaryEntryPoint`) and
//! `src/domain/dosCom.ts` (`validateDosComLength`).

/// TS `validateDosComLength(length)`.
pub(crate) fn validate_dos_com_length(length: u64) -> Result<(), String> {
    // Number.isSafeInteger holds for every u64 that reaches here (file sizes
    // are far below 2^53); the length bound is the operative check.
    if (1..=0xff00).contains(&length) {
        Ok(())
    } else {
        Err(
            "DOS COM requires 1..65280 file bytes (64 KiB segment minus the 256-byte PSP prefix)"
                .to_string(),
        )
    }
}

/// TS `validateRawBinaryLength(length)`.
fn validate_raw_binary_length(length: u64) -> Result<(), String> {
    if length >= 1 {
        Ok(())
    } else {
        Err("raw-binary requires at least one file byte".to_string())
    }
}

const BINARY_ARCHITECTURES: &[&str] = &["x86", "x86_64", "arm", "arm64", "6502", "m68k"];

fn parse_binary_architecture(value: Option<&str>) -> Option<&'static str> {
    let value = value?;
    BINARY_ARCHITECTURES
        .iter()
        .copied()
        .find(|candidate| *candidate == value)
}

/// TS `CanonicalRawBinaryEntry`.
struct CanonicalRawBinaryEntry {
    source: String,
    canonical: String,
    value: u128,
}

/// Matches the TS regex `/^0x[0-9A-Fa-f]{1,16}$/u`.
fn matches_raw_entry_point(value: &str) -> bool {
    let rest = match value.strip_prefix("0x") {
        Some(rest) => rest,
        None => return false,
    };
    !rest.is_empty() && rest.len() <= 16 && rest.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// TS `parseRawBinaryEntryPoint(value)`.
fn parse_raw_binary_entry_point(value: &str) -> Result<CanonicalRawBinaryEntry, String> {
    if !matches_raw_entry_point(value) {
        return Err("entry_point must be a hexadecimal address of the form 0x…".to_string());
    }
    // At most 16 hex digits => fits in u128 (and in u64 too, but u128 keeps the
    // width arithmetic below exact).
    let parsed = u128::from_str_radix(&value[2..], 16)
        .map_err(|_| "entry_point must be a hexadecimal address of the form 0x…".to_string())?;
    Ok(CanonicalRawBinaryEntry {
        source: value.to_string(),
        canonical: format!("0x{parsed:x}"),
        value: parsed,
    })
}

/// Rejection classification mirrors TS `RawBinaryAdmissionRejection.constraint`.
pub(crate) struct RawBinaryRejection {
    pub reason: String,
    pub constraint: &'static str,
}

/// Admitted headerless load identity (TS `RawBinaryAdmission`).
pub(crate) struct RawBinaryAdmission {
    pub architecture: &'static str,
    pub entry_point: String,
    pub entry_point_source: String,
}

fn address_width(architecture: &str) -> u128 {
    match architecture {
        "6502" => 0xffff,
        "x86" | "arm" | "m68k" => 0xffff_ffff,
        _ => 0xffff_ffff_ffff_ffff,
    }
}

/// TS `admitRawBinary({ architecture, entryPoint, fileBytes })`.
pub(crate) fn admit_raw_binary(
    architecture: Option<&str>,
    entry_point: Option<&str>,
    file_bytes: u64,
) -> Result<RawBinaryAdmission, RawBinaryRejection> {
    let architecture = match parse_binary_architecture(architecture) {
        Some(architecture) => architecture,
        None => {
            return Err(RawBinaryRejection {
                reason: "raw-binary format requires architecture (x86, x86_64, arm, arm64, 6502, or m68k)"
                    .to_string(),
                constraint: "load_selection_rejected",
            });
        }
    };
    let entry_point = match entry_point {
        Some(entry_point) => entry_point,
        None => {
            return Err(RawBinaryRejection {
                reason: "raw-binary format requires entry_point as a hexadecimal address of the form 0x…"
                    .to_string(),
                constraint: "load_selection_rejected",
            });
        }
    };
    let entry = parse_raw_binary_entry_point(entry_point).map_err(|reason| RawBinaryRejection {
        reason,
        constraint: "load_selection_rejected",
    })?;
    if (architecture == "arm" || architecture == "arm64") && entry.value % 4 != 0 {
        return Err(RawBinaryRejection {
            reason: format!(
                "raw-binary {architecture} entry_point {} must be 4-byte aligned",
                entry.canonical
            ),
            constraint: "load_selection_rejected",
        });
    }
    if architecture == "m68k" && entry.value % 2 != 0 {
        return Err(RawBinaryRejection {
            reason: format!(
                "raw-binary m68k entry_point {} must be 2-byte aligned",
                entry.canonical
            ),
            constraint: "load_selection_rejected",
        });
    }
    validate_raw_binary_length(file_bytes).map_err(|reason| RawBinaryRejection {
        reason,
        constraint: "file_format_rejected",
    })?;
    let last = entry.value + file_bytes as u128 - 1;
    let max = address_width(architecture);
    if entry.value > max || last > max {
        return Err(RawBinaryRejection {
            reason: format!(
                "raw-binary mapping from {} must fit in the {architecture} address width",
                entry.canonical
            ),
            constraint: "load_selection_rejected",
        });
    }
    Ok(RawBinaryAdmission {
        architecture,
        entry_point: entry.canonical,
        entry_point_source: entry.source,
    })
}

/// TS `rawBinarySelectionError({ format?, architecture?, entryPoint? })`.
///
/// `format` is the caller `formatHint` (`dos-com` | `raw-binary`); the TS branch
/// only distinguishes `raw-binary`.
pub(crate) fn raw_binary_selection_error(
    format: Option<&str>,
    has_architecture: bool,
    has_entry: bool,
) -> Option<String> {
    if format == Some("raw-binary") {
        if !has_architecture || !has_entry {
            return Some("format=raw-binary requires architecture and entry_point".to_string());
        }
        return None;
    }
    if has_architecture || has_entry {
        return Some("architecture and entry_point apply only with format=raw-binary".to_string());
    }
    None
}
