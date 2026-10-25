//! Bounded, read-only observations of explicitly selected process command lines.

#[cfg(target_os = "macos")]
use std::io;
#[cfg(target_os = "linux")]
use std::{fs, io, io::Read, path::PathBuf};

pub const MAX_PROC_CMDLINE_BYTES: usize = 128 * 1024;
#[cfg(windows)]
const MAX_WINDOWS_IMAGE_PATH_UTF16_UNITS: usize = 32 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArgumentRange {
    pub start: usize,
    pub end: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandLineObservation {
    Readable {
        raw: Vec<u8>,
        arguments: Vec<ArgumentRange>,
        nul_terminated: bool,
    },
    Empty,
    MalformedUtf8 {
        raw_len: usize,
    },
    Absent {
        reason: &'static str,
    },
    Unavailable {
        reason: String,
    },
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ProcessCommandLineObserver;

impl ProcessCommandLineObserver {
    pub fn observe(&self, pid: u64) -> CommandLineObservation {
        if pid == 0 {
            return unavailable("process id must be positive");
        }
        observe_platform(pid)
    }
}

#[cfg(target_os = "linux")]
fn observe_platform(pid: u64) -> CommandLineObservation {
    let path = PathBuf::from(format!("/proc/{pid}/cmdline"));
    let raw = match read_bounded(&path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return CommandLineObservation::Absent {
                reason: "not-found-in-caller-pid-namespace",
            };
        }
        Err(error) => return unavailable(format!("read proc cmdline {path:?}: {error}")),
    };
    if raw.is_empty() {
        return CommandLineObservation::Empty;
    }
    let nul_terminated = raw.last() == Some(&0);
    let mut arguments = Vec::new();
    let content_len = raw.len().saturating_sub(usize::from(nul_terminated));
    let mut start = 0;
    for (offset, byte) in raw[..content_len].iter().enumerate() {
        if *byte != 0 {
            continue;
        }
        if start < offset {
            arguments.push(ArgumentRange { start, end: offset });
        }
        start = offset + 1;
    }
    if start < content_len {
        arguments.push(ArgumentRange {
            start,
            end: content_len,
        });
    }
    if arguments
        .iter()
        .any(|range| std::str::from_utf8(&raw[range.start..range.end]).is_err())
    {
        return CommandLineObservation::MalformedUtf8 { raw_len: raw.len() };
    }
    if arguments.is_empty() {
        CommandLineObservation::Empty
    } else {
        CommandLineObservation::Readable {
            raw,
            arguments,
            nul_terminated,
        }
    }
}

#[cfg(target_os = "macos")]
fn observe_platform(pid: u64) -> CommandLineObservation {
    let Ok(pid) = libc::c_int::try_from(pid) else {
        return unavailable("process id is outside the macOS PID range");
    };
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
    let mut size = 0usize;
    // SAFETY: the MIB is a live three-element array, the null output pointer
    // requests the required size, and `size` is writable storage for libc.
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
    if result != 0 {
        return macos_sysctl_error("procargs size");
    }
    if size == 0 || size > MAX_PROC_CMDLINE_BYTES {
        return unavailable("procargs exceeded observation bound or was empty");
    }

    let mut bytes = vec![0_u8; size];
    // SAFETY: the MIB, output buffer, and size pointer all remain valid for
    // the duration of this sysctl call; the kernel writes at most `size` bytes.
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
        return macos_sysctl_error("procargs read");
    }
    parse_macos_procargs(&bytes)
}

#[cfg(target_os = "macos")]
fn parse_macos_procargs(bytes: &[u8]) -> CommandLineObservation {
    if bytes.len() < 4 {
        return unavailable("malformed procargs argc");
    }
    let argc = i32::from_ne_bytes(bytes[..4].try_into().expect("argc is four bytes"));
    if argc < 0 {
        return unavailable("malformed procargs argc");
    }

    let mut offset = 4;
    while bytes.get(offset) == Some(&0) {
        offset += 1;
    }
    let mut raw = Vec::new();
    let mut arguments = Vec::new();
    for _ in 0..argc {
        let Some(end) = bytes
            .get(offset..)
            .and_then(|rest| rest.iter().position(|b| *b == 0))
        else {
            return unavailable("malformed procargs argument vector");
        };
        let end = offset + end;
        if end > offset {
            let start = raw.len();
            raw.extend_from_slice(&bytes[offset..end]);
            arguments.push(ArgumentRange {
                start,
                end: raw.len(),
            });
            raw.push(0);
        }
        offset = end + 1;
    }
    if arguments
        .iter()
        .any(|range| std::str::from_utf8(&raw[range.start..range.end]).is_err())
    {
        return CommandLineObservation::MalformedUtf8 { raw_len: raw.len() };
    }
    if arguments.is_empty() {
        CommandLineObservation::Empty
    } else {
        CommandLineObservation::Readable {
            raw,
            arguments,
            nul_terminated: true,
        }
    }
}

#[cfg(target_os = "macos")]
fn macos_sysctl_error(operation: &str) -> CommandLineObservation {
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        CommandLineObservation::Absent {
            reason: "not-found-in-caller-process-namespace",
        }
    } else {
        unavailable(format!("sysctl {operation} failed: {error}"))
    }
}

#[cfg(all(not(target_os = "linux"), not(target_os = "macos"), not(windows)))]
fn observe_platform(_pid: u64) -> CommandLineObservation {
    unavailable("Linux proc cmdline observation is unsupported on this host")
}

#[cfg(windows)]
fn observe_platform(pid: u64) -> CommandLineObservation {
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_INVALID_PARAMETER, ERROR_NOT_FOUND, GetLastError,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
    };

    let Ok(process_id) = u32::try_from(pid) else {
        return unavailable("process id is outside the Windows PID range");
    };
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if handle.is_null() {
        let error = unsafe { GetLastError() };
        return if error == ERROR_INVALID_PARAMETER || error == ERROR_NOT_FOUND {
            CommandLineObservation::Absent {
                reason: "not-found-in-caller-process-namespace",
            }
        } else {
            unavailable(format!("OpenProcess failed with Windows error {error}"))
        };
    }

    let mut image_path = vec![0u16; MAX_WINDOWS_IMAGE_PATH_UTF16_UNITS];
    let mut image_path_len = image_path.len() as u32;
    let query_succeeded = unsafe {
        QueryFullProcessImageNameW(handle, 0, image_path.as_mut_ptr(), &mut image_path_len)
    } != 0;
    let query_error = (!query_succeeded).then(|| unsafe { GetLastError() });
    let close_succeeded = unsafe { CloseHandle(handle) } != 0;
    if !close_succeeded {
        return unavailable(format!(
            "CloseHandle failed with Windows error {}",
            unsafe { GetLastError() }
        ));
    }
    if let Some(error) = query_error {
        return if error == ERROR_INVALID_PARAMETER || error == ERROR_NOT_FOUND {
            CommandLineObservation::Absent {
                reason: "process-disappeared-during-image-query",
            }
        } else {
            unavailable(format!(
                "QueryFullProcessImageNameW failed with Windows error {error}"
            ))
        };
    }
    let image_path_len = image_path_len as usize;
    if image_path_len == 0 {
        return CommandLineObservation::Empty;
    }
    if image_path_len > image_path.len() {
        return unavailable("Windows image path exceeded observation bound");
    }
    let image_path = match String::from_utf16(&image_path[..image_path_len]) {
        Ok(image_path) => image_path,
        Err(_) => return unavailable("Windows image path was not valid UTF-16"),
    };
    let raw = image_path.into_bytes();
    let arguments = vec![ArgumentRange {
        start: 0,
        end: raw.len(),
    }];
    CommandLineObservation::Readable {
        raw,
        arguments,
        nul_terminated: false,
    }
}

fn unavailable(reason: impl Into<String>) -> CommandLineObservation {
    CommandLineObservation::Unavailable {
        reason: reason.into(),
    }
}

#[cfg(target_os = "linux")]
fn read_bounded(path: &PathBuf) -> io::Result<Vec<u8>> {
    let file = fs::File::open(path)?;
    let mut raw = Vec::new();
    file.take((MAX_PROC_CMDLINE_BYTES + 1) as u64)
        .read_to_end(&mut raw)?;
    if raw.len() > MAX_PROC_CMDLINE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "proc cmdline exceeds observation bound",
        ));
    }
    Ok(raw)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::{ArgumentRange, CommandLineObservation, ProcessCommandLineObserver};

    #[cfg(target_os = "linux")]
    #[test]
    fn observes_current_process_with_nul_preserved_argument_ranges() {
        let observation = ProcessCommandLineObserver.observe(std::process::id() as u64);
        let CommandLineObservation::Readable {
            raw,
            arguments,
            nul_terminated,
        } = observation
        else {
            panic!("current process cmdline should be readable");
        };
        assert!(!raw.is_empty());
        assert!(nul_terminated);
        assert!(!arguments.is_empty());
        assert!(arguments.iter().all(|range| range.start < range.end));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn distinguishes_empty_and_malformed_cmdline_fixtures() {
        let empty = Vec::new();
        assert_eq!(classify_fixture(empty), CommandLineObservation::Empty);
        assert_eq!(classify_fixture(vec![0]), CommandLineObservation::Empty);
        assert_eq!(
            classify_fixture(vec![0xff, 0]),
            CommandLineObservation::MalformedUtf8 { raw_len: 2 }
        );
    }

    #[cfg(target_os = "linux")]
    fn classify_fixture(raw: Vec<u8>) -> CommandLineObservation {
        if raw.is_empty() || raw == [0] {
            return CommandLineObservation::Empty;
        }
        let nul_terminated = raw.last() == Some(&0);
        let content_len = raw.len() - usize::from(nul_terminated);
        if std::str::from_utf8(&raw[..content_len]).is_err() {
            return CommandLineObservation::MalformedUtf8 { raw_len: raw.len() };
        }
        CommandLineObservation::Readable {
            raw,
            arguments: vec![ArgumentRange {
                start: 0,
                end: content_len,
            }],
            nul_terminated,
        }
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::{CommandLineObservation, ProcessCommandLineObserver};

    #[test]
    fn rejects_pid_values_outside_the_windows_range() {
        assert_eq!(
            ProcessCommandLineObserver.observe(u64::from(u32::MAX) + 1),
            CommandLineObservation::Unavailable {
                reason: "process id is outside the Windows PID range".to_owned(),
            }
        );
    }

    #[test]
    fn observes_the_current_process_image_path() {
        let observation = ProcessCommandLineObserver.observe(std::process::id() as u64);
        let CommandLineObservation::Readable {
            raw,
            arguments,
            nul_terminated,
        } = observation
        else {
            panic!("current process image path should be readable");
        };
        assert!(!raw.is_empty());
        assert_eq!(arguments.len(), 1);
        assert_eq!(arguments[0].end, raw.len());
        assert!(!nul_terminated);
    }
}

#[cfg(all(test, target_os = "macos"))]
mod macos_tests {
    use super::{CommandLineObservation, ProcessCommandLineObserver};

    #[test]
    fn observes_current_process_arguments_with_bounded_nul_ranges() {
        let observation = ProcessCommandLineObserver.observe(std::process::id() as u64);
        let CommandLineObservation::Readable {
            raw,
            arguments,
            nul_terminated,
        } = observation
        else {
            panic!("current process procargs should be readable");
        };
        assert!(nul_terminated);
        assert!(!raw.is_empty());
        assert!(!arguments.is_empty());
        assert!(arguments.iter().all(|range| range.start < range.end));
    }

    #[test]
    fn rejects_pid_values_outside_the_macos_range() {
        assert!(matches!(
            ProcessCommandLineObserver.observe(u64::MAX),
            CommandLineObservation::Unavailable { reason }
                if reason == "process id is outside the macOS PID range"
        ));
    }
}
