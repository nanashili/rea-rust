//! Darwin capture run-token reader.
//!
//! Compatibility owner: `bridge/process/ProcessRunTokenReader.swift` (the
//! original runtime compiled it per run). Each token read is bracketed by
//! two identity reads of the same PID so a token is never attributed to a
//! replaced generation, and an empty environment is classified with the
//! kernel's code-signing flags because macOS withholds the environment of
//! platform binaries and `CS_RESTRICT` processes from `KERN_PROCARGS2`.
//! Reason strings are the original reader's codes.

const RUN_TOKEN_PREFIX: &[u8] = b"REA_PROCESS_RUN_ID=";
const CS_OPS_STATUS: u32 = 0;
const CS_PLATFORM_BINARY: u32 = 0x0400_0000;
const CS_RESTRICT: u32 = 0x0000_0800;
const MAX_PROCARGS_BYTES: usize = 1024 * 1024;

/// One run-token observation (`RunTokenObservation` of the original reader).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DarwinRunToken {
    /// The environment was readable; `run_id` is absent when it has no token.
    Readable {
        run_id: Option<String>,
    },
    Unavailable {
        reason: String,
    },
}

/// Facts of one PID read through `PROC_PIDTBSDINFO`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DarwinProcessFacts {
    /// `start_sec:start_usec`, the same identity as the process observer.
    pub identity: String,
    pub pointer_size: usize,
}

enum ParseFailure {
    InvalidBuffer,
    DuplicateToken,
    InvalidTokenEncoding,
    EnvironmentUnavailable,
    AppleVectorUnavailable,
    AmbiguousEnvironmentBoundary,
}

struct ParsedRunToken {
    run_id: Option<String>,
    environment_entries: usize,
}

unsafe extern "C" {
    fn csops(
        pid: libc::pid_t,
        ops: u32,
        useraddr: *mut libc::c_void,
        usersize: libc::size_t,
    ) -> libc::c_int;
}

fn errno() -> i32 {
    // SAFETY: __error returns Darwin's thread-local errno slot.
    unsafe { *libc::__error() }
}

/// Read one PID's identity facts from the kernel process table; `Err`
/// carries the original snapshot reason.
pub fn process_facts(pid: libc::pid_t) -> Result<DarwinProcessFacts, String> {
    let pid = u32::try_from(pid).map_err(|_| "invalid_process_id".to_owned())?;
    match super::process_table::process(pid)? {
        Some(process) => Ok(DarwinProcessFacts {
            identity: process.identity,
            pointer_size: process.pointer_size,
        }),
        None => Err("process_not_in_snapshot".to_owned()),
    }
}

fn code_signing_flags(pid: libc::pid_t) -> Option<u32> {
    let mut flags: u32 = 0;
    // SAFETY: csops(CS_OPS_STATUS) writes one u32 into the provided buffer.
    let result = unsafe {
        csops(
            pid,
            CS_OPS_STATUS,
            (&raw mut flags).cast(),
            std::mem::size_of::<u32>(),
        )
    };
    (result == 0).then_some(flags)
}

fn read_procargs(pid: libc::pid_t) -> Result<Vec<u8>, String> {
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
    let mut size: libc::size_t = 0;
    // SAFETY: three-component MIB; a null output only queries the size.
    let result = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            std::ptr::null_mut(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if result != 0 || size < 4 {
        return Err(format!("sysctl_failed_{}", errno()));
    }
    if size > MAX_PROCARGS_BYTES {
        return Err("malformed_procargs".to_owned());
    }
    let mut bytes = vec![0_u8; size];
    // SAFETY: the owned buffer has the size reported by the preceding query.
    let result = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            bytes.as_mut_ptr().cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if result != 0 {
        return Err(format!("sysctl_failed_{}", errno()));
    }
    bytes.truncate(size);
    Ok(bytes)
}

fn read_string<'a>(bytes: &'a [u8], offset: &mut usize, allow_empty: bool) -> Option<&'a [u8]> {
    let rest = bytes.get(*offset..)?;
    let end = rest.iter().position(|byte| *byte == 0)?;
    if !allow_empty && end == 0 {
        return None;
    }
    let value = &rest[..end];
    *offset += end + 1;
    Some(value)
}

fn parse_environment(bytes: &[u8], pointer_size: usize) -> Result<ParsedRunToken, ParseFailure> {
    use ParseFailure::*;
    let argc = i32::from_le_bytes(
        bytes
            .get(..4)
            .ok_or(InvalidBuffer)?
            .try_into()
            .map_err(|_| InvalidBuffer)?,
    );
    if argc < 0 || argc as usize > bytes.len() {
        return Err(InvalidBuffer);
    }
    let mut offset = 4;
    let executable = read_string(bytes, &mut offset, false).ok_or(InvalidBuffer)?;
    if pointer_size != 4 && pointer_size != 8 {
        return Err(InvalidBuffer);
    }
    let record = b"executable_path=".len() + executable.len() + 1;
    let padding = (pointer_size - record % pointer_size) % pointer_size;
    if offset + padding > bytes.len() || bytes[offset..offset + padding].iter().any(|b| *b != 0) {
        return Err(InvalidBuffer);
    }
    offset += padding;
    for _ in 0..argc {
        read_string(bytes, &mut offset, true).ok_or(InvalidBuffer)?;
    }
    if bytes.last() != Some(&0) {
        return Err(InvalidBuffer);
    }
    if offset == bytes.len() {
        return Err(EnvironmentUnavailable);
    }
    let mut entries: Vec<&[u8]> = Vec::new();
    let mut zeroed_start = None;
    while offset < bytes.len() {
        if bytes[offset] == 0 {
            let start = offset;
            while offset < bytes.len() && bytes[offset] == 0 {
                offset += 1;
            }
            if offset - start > 1 {
                zeroed_start.get_or_insert(entries.len());
            }
            continue;
        }
        entries.push(read_string(bytes, &mut offset, false).ok_or(InvalidBuffer)?);
    }
    // XNU appends the Apple vector after the environment; libc clears its
    // initial `pfz=` record, leaving a multi-NUL run in its place.
    let intact = entries.iter().rposition(|entry| entry.starts_with(b"pfz="));
    let prefer_zeroed =
        zeroed_start.is_some_and(|zeroed| intact.is_none_or(|intact| intact < zeroed));
    let apple_start =
        if prefer_zeroed { zeroed_start } else { intact }.ok_or(AppleVectorUnavailable)?;
    if entries[apple_start..]
        .iter()
        .any(|entry| entry.starts_with(RUN_TOKEN_PREFIX))
    {
        return Err(AmbiguousEnvironmentBoundary);
    }
    let environment = &entries[..apple_start];
    let mut found = None;
    for entry in environment {
        if let Some(value) = entry.strip_prefix(RUN_TOKEN_PREFIX) {
            if found.is_some() {
                return Err(DuplicateToken);
            }
            found = Some(String::from_utf8(value.to_vec()).map_err(|_| InvalidTokenEncoding)?);
        }
    }
    Ok(ParsedRunToken {
        run_id: found,
        environment_entries: environment.len(),
    })
}

fn unavailable(reason: &str) -> DarwinRunToken {
    DarwinRunToken::Unavailable {
        reason: reason.to_owned(),
    }
}

fn classify(
    parse: Result<ParsedRunToken, ParseFailure>,
    flags: impl Fn() -> Option<u32>,
) -> DarwinRunToken {
    let withheld = |fallback: &str| match flags() {
        Some(flags) if flags & CS_PLATFORM_BINARY != 0 => {
            unavailable("platform_binary_environment_withheld")
        }
        Some(flags) if flags & CS_RESTRICT != 0 => {
            unavailable("restricted_process_environment_withheld")
        }
        _ => match fallback {
            "" => DarwinRunToken::Readable { run_id: None },
            reason => unavailable(reason),
        },
    };
    match parse {
        Ok(parsed) if parsed.run_id.is_some() => DarwinRunToken::Readable {
            run_id: parsed.run_id,
        },
        // A non-empty environment without the token proves the process is unrelated.
        Ok(parsed) if parsed.environment_entries > 0 => DarwinRunToken::Readable { run_id: None },
        Ok(_) => withheld(""),
        Err(ParseFailure::EnvironmentUnavailable) => withheld("environment_unavailable"),
        Err(ParseFailure::AmbiguousEnvironmentBoundary) => match flags() {
            Some(flags) if flags & CS_RESTRICT != 0 => {
                unavailable("restricted_process_environment_withheld")
            }
            _ => unavailable("ambiguous_environment_boundary"),
        },
        Err(ParseFailure::DuplicateToken) => unavailable("duplicate_run_token"),
        Err(ParseFailure::InvalidTokenEncoding) => unavailable("invalid_run_token_encoding"),
        Err(ParseFailure::AppleVectorUnavailable) => unavailable("apple_vector_unavailable"),
        Err(ParseFailure::InvalidBuffer) => unavailable("malformed_procargs"),
    }
}

fn read_one(pid: libc::pid_t, pointer_size: usize) -> DarwinRunToken {
    let bytes = match read_procargs(pid) {
        Ok(bytes) => bytes,
        Err(reason) => return unavailable(&reason),
    };
    classify(parse_environment(&bytes, pointer_size), || {
        code_signing_flags(pid)
    })
}

/// The argument vector from `KERN_PROCARGS2` (what `ps -o command` prints).
pub fn read_arguments(pid: libc::pid_t) -> Result<Vec<String>, String> {
    let pointer_size = process_facts(pid)?.pointer_size;
    let bytes = read_procargs(pid)?;
    let malformed = || "malformed_procargs".to_owned();
    let argc = i32::from_le_bytes(
        bytes
            .get(..4)
            .ok_or_else(malformed)?
            .try_into()
            .map_err(|_| malformed())?,
    );
    if argc < 0 {
        return Err(malformed());
    }
    let mut offset = 4;
    let executable = read_string(&bytes, &mut offset, false).ok_or_else(malformed)?;
    let record = b"executable_path=".len() + executable.len() + 1;
    // Skip the alignment padding (and any extra NULs) before argv[0].
    offset += (pointer_size - record % pointer_size) % pointer_size;
    while bytes.get(offset) == Some(&0) {
        offset += 1;
    }
    (0..argc)
        .map(|_| {
            read_string(&bytes, &mut offset, true)
                .map(|argument| String::from_utf8_lossy(argument).into_owned())
                .ok_or_else(malformed)
        })
        .collect()
}

/// `readRunTokens`: read each PID's token between two identity reads.
pub fn read_run_tokens(pids: &[libc::pid_t]) -> Vec<DarwinRunToken> {
    let before: Vec<_> = pids.iter().map(|pid| process_facts(*pid)).collect();
    let observations: Vec<_> = pids
        .iter()
        .zip(&before)
        .map(|(pid, facts)| match facts {
            Ok(facts) => read_one(*pid, facts.pointer_size),
            Err(reason) => unavailable(reason),
        })
        .collect();
    pids.iter()
        .zip(before)
        .zip(observations)
        .map(
            |((pid, before), observation)| match (before, process_facts(*pid)) {
                (Ok(initial), Ok(current)) if initial == current => observation,
                (Ok(_), Ok(_)) => unavailable("process_identity_changed_during_token_read"),
                (_, Err(reason)) => unavailable(&reason),
                (Err(_), Ok(_)) => unavailable("process_not_in_snapshot"),
            },
        )
        .collect()
}

/// Read one PID's token (`readRunTokens([pid])`).
pub fn read_run_token(pid: libc::pid_t) -> DarwinRunToken {
    read_run_tokens(&[pid])
        .pop()
        .unwrap_or_else(|| unavailable("reader_failure"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn procargs(arguments: &[&[u8]], environment: &[&[u8]], apple: &[&[u8]]) -> Vec<u8> {
        let mut bytes = (arguments.len() as i32).to_le_bytes().to_vec();
        let executable = b"/bin/tool";
        bytes.extend_from_slice(executable);
        bytes.push(0);
        let record = b"executable_path=".len() + executable.len() + 1;
        bytes.extend(std::iter::repeat_n(0, (8 - record % 8) % 8));
        for argument in arguments {
            bytes.extend_from_slice(argument);
            bytes.push(0);
        }
        for entry in environment {
            bytes.extend_from_slice(entry);
            bytes.push(0);
        }
        bytes.extend_from_slice(b"\0\0");
        for entry in apple {
            bytes.extend_from_slice(entry);
            bytes.push(0);
        }
        bytes
    }

    #[test]
    fn reads_token_before_the_apple_vector() {
        let bytes = procargs(
            &[b"tool"],
            &[b"A=1", b"REA_PROCESS_RUN_ID=run-1"],
            &[b"ptr_munge="],
        );
        let parsed = parse_environment(&bytes, 8).ok().unwrap();
        assert_eq!(parsed.run_id.as_deref(), Some("run-1"));
        assert_eq!(parsed.environment_entries, 2);
    }

    #[test]
    fn token_in_apple_vector_is_ambiguous() {
        let bytes = procargs(&[b"tool"], &[b"A=1"], &[b"REA_PROCESS_RUN_ID=x"]);
        assert!(matches!(
            parse_environment(&bytes, 8),
            Err(ParseFailure::AmbiguousEnvironmentBoundary)
        ));
    }

    #[test]
    fn empty_environment_is_classified_by_code_signing_flags() {
        let empty = || {
            Ok(ParsedRunToken {
                run_id: None,
                environment_entries: 0,
            })
        };
        assert_eq!(
            classify(empty(), || Some(CS_PLATFORM_BINARY)),
            unavailable("platform_binary_environment_withheld")
        );
        assert_eq!(
            classify(empty(), || Some(CS_RESTRICT)),
            unavailable("restricted_process_environment_withheld")
        );
        assert_eq!(
            classify(empty(), || None),
            DarwinRunToken::Readable { run_id: None }
        );
        assert_eq!(
            classify(Err(ParseFailure::EnvironmentUnavailable), || None),
            unavailable("environment_unavailable")
        );
    }

    #[test]
    fn duplicate_tokens_fail_closed() {
        let bytes = procargs(
            &[],
            &[b"REA_PROCESS_RUN_ID=a", b"REA_PROCESS_RUN_ID=b"],
            &[b"pfz=1"],
        );
        assert!(matches!(
            parse_environment(&bytes, 8),
            Err(ParseFailure::DuplicateToken)
        ));
    }

    #[test]
    fn reads_own_process_identity_and_absent_pid() {
        let own = std::process::id() as libc::pid_t;
        assert!(process_facts(own).is_ok());
        assert_eq!(
            process_facts(i32::MAX).unwrap_err(),
            "process_not_in_snapshot"
        );
    }
}
