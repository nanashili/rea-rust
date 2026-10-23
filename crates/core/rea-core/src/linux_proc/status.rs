//! Effective UID from one Linux status record, not from process-list display text.
//!
//! Compatibility owner: `src/process/LinuxProcessStatus.ts`. A malformed or
//! duplicate native UID row does not establish that a process belongs to a user.

use crate::linux_proc::text::{contract_whitespace, safe_decimal};
use std::fmt;

/// Why the status record cannot establish an effective UID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseError {
    /// No exact `Uid:` row was present.
    MissingUid,
    /// More than one exact `Uid:` row was present.
    DuplicateUid,
    /// The row did not contain exactly four supported unsigned decimal values.
    InvalidUid,
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MissingUid => "missing native Uid row",
            Self::DuplicateUid => "duplicate native Uid row",
            Self::InvalidUid => "invalid native Uid row",
        })
    }
}

impl std::error::Error for ParseError {}

/// Read the effective (second) UID after validating all four native UID values.
///
/// The complete record is checked for duplicate rows. No heap storage is used.
/// A caller must bracket this observation with process identity checks before
/// attributing it to a previously observed PID.
///
/// # Errors
/// Missing, malformed, out-of-range and duplicate rows return tagged failures;
/// they must not be interpreted as an absent process or a different user.
pub fn effective_uid(value: &str) -> Result<u64, ParseError> {
    let mut effective = None;
    for line in value.split('\n') {
        let Some(row) = line.strip_prefix("Uid:") else {
            continue;
        };
        if effective.is_some() {
            return Err(ParseError::DuplicateUid);
        }
        if !row.starts_with(contract_whitespace) {
            return Err(ParseError::InvalidUid);
        }
        let mut values = row
            .split(contract_whitespace)
            .filter(|part| !part.is_empty());
        for index in 0..4 {
            let uid = values
                .next()
                .and_then(safe_decimal)
                .ok_or(ParseError::InvalidUid)?;
            if index == 1 {
                effective = Some(uid);
            }
        }
        if values.next().is_some() {
            return Err(ParseError::InvalidUid);
        }
    }
    effective.ok_or(ParseError::MissingUid)
}
