//! Parse Linux process facts without acquiring process-control authority.
//!
//! Compatibility owner: `src/process/LinuxProcessStat.ts`. Identity and relations
//! survive unknown task flags. None of these observations alone proves ownership.

use crate::linux_proc::text::{contract_whitespace, decimal, safe_decimal};
use std::fmt;

/// Observed lifecycle, distinct from authenticated ownership or confirmed exit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Lifecycle {
    /// The task has become a zombie.
    Zombie,
    /// The native state is X or x.
    Dead,
    /// PF_EXITING is set, but no terminal state was observed.
    Exiting,
    /// No terminal state or PF_EXITING flag was observed.
    NonZombie,
}

/// Facts from one record. The start-time spelling borrows the original input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessStat<'a> {
    /// Positive process ID within the existing contract's safe-integer range.
    pub pid: u64,
    /// Exact decimal field 22, without narrowing or stripping leading zeroes.
    pub start_time: &'a str,
    /// Unknown when nonterminal state is accompanied by invalid task flags.
    pub lifecycle: Option<Lifecycle>,
    /// Native parent process ID; zero remains a valid observation.
    pub parent_pid: u64,
    /// Native process-group ID; zero remains a valid observation.
    pub process_group_id: u64,
    /// Native session ID; zero remains a valid observation.
    pub session_id: u64,
}

/// A record cannot establish the required process identity and relation facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseError {
    /// Missing or misordered command parentheses.
    Command,
    /// Missing, zero, malformed or out-of-range process ID.
    Pid,
    /// A required procfs field is absent (one-based native field number).
    MissingField(u8),
    /// A required procfs field is malformed or outside its supported range.
    InvalidField(u8),
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Command => formatter.write_str("invalid process command delimiters"),
            Self::Pid => formatter.write_str("invalid process id"),
            Self::MissingField(field) => write!(formatter, "missing procfs field {field}"),
            Self::InvalidField(field) => write!(formatter, "invalid procfs field {field}"),
        }
    }
}

impl std::error::Error for ParseError {}

/// Parse one textual `/proc/<pid>/stat` record with no heap allocation.
///
/// Uses the final closing parenthesis because command names may contain spaces,
/// newlines and parentheses. Trailing native fields are not materialized. State
/// letters outside known terminal states retain the existing nonterminal rules.
///
/// # Errors
/// Returns a tagged error when identity, state or relation fields are missing or
/// invalid. Invalid flags retain these facts with an unknown lifecycle instead.
pub fn parse(value: &str) -> Result<ProcessStat<'_>, ParseError> {
    let start = value.find('(').ok_or(ParseError::Command)?;
    let end = value.rfind(')').ok_or(ParseError::Command)?;
    if start == 0 || end <= start {
        return Err(ParseError::Command);
    }
    let pid = safe_decimal(value[..start].trim_matches(contract_whitespace))
        .filter(|pid| *pid != 0)
        .ok_or(ParseError::Pid)?;
    let mut fields = value[end + 1..]
        .split(contract_whitespace)
        .filter(|field| !field.is_empty());
    let state = fields.next().ok_or(ParseError::MissingField(3))?;
    if state.len() != 1 || !state.as_bytes()[0].is_ascii_alphabetic() {
        return Err(ParseError::InvalidField(3));
    }
    let mut relation = |number| {
        let text = fields.next().ok_or(ParseError::MissingField(number))?;
        safe_decimal(text).ok_or(ParseError::InvalidField(number))
    };
    let parent_pid = relation(4)?;
    let process_group_id = relation(5)?;
    let session_id = relation(6)?;
    let flags = fields.nth(2).and_then(safe_decimal); // field 9
    let start_time = fields.nth(12).ok_or(ParseError::MissingField(22))?;
    if !decimal(start_time) {
        return Err(ParseError::InvalidField(22));
    }
    let lifecycle = match state {
        "Z" => Some(Lifecycle::Zombie),
        "X" | "x" => Some(Lifecycle::Dead),
        _ => flags.map(|flags| {
            if flags & 4 != 0 {
                Lifecycle::Exiting
            } else {
                Lifecycle::NonZombie
            }
        }),
    };
    Ok(ProcessStat {
        pid,
        start_time,
        lifecycle,
        parent_pid,
        process_group_id,
        session_id,
    })
}
