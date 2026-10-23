//! Versioned C embedding interface for REA process-fact parsing.
//!
//! The safe core owns interpretation. This adapter owns pointer validation,
//! stable C layout, byte offsets and panic containment. It grants no authority
//! to inspect or control a live process. See `include/rea.h` for the C contract.

use rea_core::linux_proc::{
    self,
    stat::{Lifecycle, ParseError},
};
use std::{mem, panic, ptr, slice, str};

/// Successful parse.
pub const OK: u32 = 0;
/// Null, oversized, or incompatible buffer argument.
pub const INVALID_ARGUMENT: u32 = 1;
/// Input is not UTF-8; no replacement or lossy interpretation was performed.
pub const INVALID_UTF8: u32 = 2;
/// Required process facts cannot be established; see the result's error fields.
pub const INVALID_RECORD: u32 = 3;
/// A Rust panic was caught before crossing the C interface.
pub const INTERNAL_ERROR: u32 = 4;

/// No exact native UID row was found.
pub const STATUS_MISSING_UID: u32 = 1;
/// More than one exact native UID row was found.
pub const STATUS_DUPLICATE_UID: u32 = 2;
/// The native UID row was malformed or out of range.
pub const STATUS_INVALID_UID: u32 = 3;

/// Stable v1 result layout. All fields are initialized, including on parse error.
///
/// Start-time offset and length refer to the caller's original input. No memory
/// is retained or allocated for the result. See the C header for numeric tags.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ProcessStatV1 {
    /// Native process ID.
    pub pid: u64,
    /// Native parent process ID.
    pub parent_pid: u64,
    /// Native process-group ID.
    pub process_group_id: u64,
    /// Native session ID.
    pub session_id: u64,
    /// Byte offset of the exact start-time field in the caller's input.
    pub start_time_offset: usize,
    /// Byte length of the exact start-time field.
    pub start_time_length: usize,
    /// 0 unknown, 1 non-zombie, 2 exiting, 3 zombie, 4 dead.
    pub lifecycle: u32,
    /// 0 none, 1 command delimiters, 2 PID, 3 missing field, 4 invalid field.
    pub error_kind: u32,
    /// One-based procfs field number when error_kind is 3 or 4; otherwise zero.
    pub error_field: u32,
    /// Reserved, always zero in v1.
    pub reserved: u32,
}

/// Stable v1 projection of the effective UID in a Linux `/proc/<pid>/status` record.
///
/// The parser does not establish process identity or ownership. Callers must
/// associate this record with a process only after checking the process
/// generation around the read. Every field is initialized on parse failures.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ProcessStatusV1 {
    /// Effective UID, valid only when the function returns [`OK`].
    pub effective_uid: u64,
    /// 0 none, 1 missing Uid row, 2 duplicate Uid row, 3 invalid Uid row.
    pub error_kind: u32,
    /// Reserved, always zero in v1.
    pub reserved: u32,
}

/// Parse process facts into a caller-owned v1 result.
///
/// No allocation ownership crosses the interface. `out_size` must equal the v1
/// layout size. Invalid arguments leave output untouched. Other failures zero
/// facts and set parse error details when available. The function never retains
/// input or output pointers. Rust unwinding is caught; invalid memory from a
/// caller, aborting panics and process-level failures cannot be contained here.
///
/// # Safety
/// For nonzero length, `input` must point to `input_length` initialized bytes in
/// one allocation, immutable for the call. A null input is allowed only for zero
/// length. `out` must point to writable, aligned storage for `ProcessStatV1` and
/// must not overlap input. No other thread may access output during the call.
/// Pointer validity and allocation extent cannot be inferred from their values.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rea_parse_linux_process_stat_v1(
    input: *const u8,
    input_length: usize,
    out: *mut ProcessStatV1,
    out_size: usize,
) -> u32 {
    if out.is_null()
        || out_size != mem::size_of::<ProcessStatV1>()
        || !out.is_aligned()
        || (input.is_null() && input_length != 0)
        || input_length > isize::MAX as usize
    {
        return INVALID_ARGUMENT;
    }
    let outcome = panic::catch_unwind(|| {
        let bytes = if input_length == 0 {
            &[][..]
        } else {
            // SAFETY: the caller guarantees a single readable immutable input
            // allocation. Null and lengths exceeding isize::MAX were rejected.
            unsafe { slice::from_raw_parts(input, input_length) }
        };
        parse_bytes(bytes)
    });
    let (status, result) = match outcome {
        Ok(result) => result,
        Err(payload) => {
            // A custom panic payload may panic on drop. This exceptional path
            // intentionally leaks it rather than unwinding across the C ABI.
            mem::forget(payload);
            (INTERNAL_ERROR, ProcessStatV1::default())
        }
    };
    // SAFETY: caller guarantees writable, non-overlapping result storage; null,
    // alignment and layout size were checked before accessing input or output.
    unsafe { ptr::write(out, result) };
    status
}

/// Parse the effective UID from a caller-owned Linux process status record.
///
/// The output size must equal the v1 layout size. Invalid arguments leave the
/// output untouched. Other failures zero facts and set `error_kind` when the
/// record is malformed. The function does not retain either pointer.
///
/// # Safety
/// For nonzero length, `input` must point to `input_length` initialized bytes in
/// one allocation and remain immutable for the call. A null input is allowed
/// only for zero length. `out` must point to writable, aligned storage for
/// `ProcessStatusV1` and must not overlap input. No other thread may access the
/// output during the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rea_parse_linux_process_status_v1(
    input: *const u8,
    input_length: usize,
    out: *mut ProcessStatusV1,
    out_size: usize,
) -> u32 {
    if out.is_null()
        || out_size != mem::size_of::<ProcessStatusV1>()
        || !out.is_aligned()
        || (input.is_null() && input_length != 0)
        || input_length > isize::MAX as usize
    {
        return INVALID_ARGUMENT;
    }

    let outcome = panic::catch_unwind(|| {
        let bytes = if input_length == 0 {
            &[][..]
        } else {
            // SAFETY: the caller guarantees one readable immutable allocation.
            unsafe { slice::from_raw_parts(input, input_length) }
        };

        parse_status_bytes(bytes)
    });

    let (status, result) = match outcome {
        Ok(result) => result,
        Err(payload) => {
            // Keep custom panic-payload destructors from unwinding over C.
            mem::forget(payload);
            (INTERNAL_ERROR, ProcessStatusV1::default())
        }
    };

    // SAFETY: output validity, size, alignment and non-overlap are caller
    // guarantees documented above; pointer shape was checked before parsing.
    unsafe { ptr::write(out, result) };
    status
}

fn parse_bytes(bytes: &[u8]) -> (u32, ProcessStatV1) {
    let mut result = ProcessStatV1::default();
    let Ok(text) = str::from_utf8(bytes) else {
        return (INVALID_UTF8, result);
    };
    match linux_proc::stat::parse(text) {
        Ok(facts) => {
            result.pid = facts.pid;
            result.parent_pid = facts.parent_pid;
            result.process_group_id = facts.process_group_id;
            result.session_id = facts.session_id;
            // The safe parser returns a slice of text, not a separate string.
            result.start_time_offset = facts.start_time.as_ptr() as usize - text.as_ptr() as usize;
            result.start_time_length = facts.start_time.len();
            result.lifecycle = match facts.lifecycle {
                None => 0,
                Some(Lifecycle::NonZombie) => 1,
                Some(Lifecycle::Exiting) => 2,
                Some(Lifecycle::Zombie) => 3,
                Some(Lifecycle::Dead) => 4,
            };
            (OK, result)
        }
        Err(error) => {
            (result.error_kind, result.error_field) = match error {
                ParseError::Command => (1, 0),
                ParseError::Pid => (2, 0),
                ParseError::MissingField(field) => (3, u32::from(field)),
                ParseError::InvalidField(field) => (4, u32::from(field)),
            };
            (INVALID_RECORD, result)
        }
    }
}

fn parse_status_bytes(bytes: &[u8]) -> (u32, ProcessStatusV1) {
    let mut result = ProcessStatusV1::default();
    let Ok(text) = str::from_utf8(bytes) else {
        return (INVALID_UTF8, result);
    };

    match linux_proc::status::effective_uid(text) {
        Ok(effective_uid) => {
            result.effective_uid = effective_uid;
            (OK, result)
        }
        Err(error) => {
            result.error_kind = match error {
                linux_proc::status::ParseError::MissingUid => STATUS_MISSING_UID,
                linux_proc::status::ParseError::DuplicateUid => STATUS_DUPLICATE_UID,
                linux_proc::status::ParseError::InvalidUid => STATUS_INVALID_UID,
            };
            (INVALID_RECORD, result)
        }
    }
}
