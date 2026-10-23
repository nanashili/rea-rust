//! Provider-neutral command construction for the reverse-engineering family.
//!
//! Compatibility owners: `src/objdump/ObjdumpCommand.ts`,
//! `src/rizin/RizinCommand.ts`, `src/filesystem/callerPath.ts`,
//! `src/composition/reverseEngineering.ts` and
//! `src/composition/resolveWindowsProviderExecutable.ts`.
use rea_core::evidence::envelope::EvidenceProvider;
use serde_json::Value;
use std::collections::HashMap;

/// `OBJDUMP_PROVIDER_IDENTITY`.
pub fn objdump_identity() -> EvidenceProvider {
    EvidenceProvider::new("gnu.objdump", "GNU objdump", None)
}

/// `RIZIN_PROVIDER_IDENTITY`.
pub fn rizin_identity() -> EvidenceProvider {
    EvidenceProvider::new("rizin", "Rizin", None)
}

/// One provider-neutral command profile (`ReverseEngineeringProviderCommand`).
pub struct ProviderCommand {
    pub executable: String,
    pub arguments: Vec<String>,
    pub identity: EvidenceProvider,
    /// Additional environment applied over the session snapshot.
    pub environment_overrides: Vec<(&'static str, String)>,
}

/// `createReverseEngineeringCommandPort(...).objdump(input)`.
pub fn objdump_command(input: &Value, environment: &HashMap<String, String>) -> ProviderCommand {
    let executable = provider_executable(
        environment
            .get("REA_OBJDUMP_COMMAND")
            .cloned()
            .unwrap_or_else(|| "objdump".to_owned()),
        environment,
    );
    ProviderCommand {
        executable,
        arguments: objdump_arguments(input),
        identity: objdump_identity(),
        environment_overrides: vec![("DEBUGINFOD_URLS", String::new())],
    }
}

/// `createReverseEngineeringCommandPort(...).rizin(input)`.
pub fn rizin_command(input: &Value, environment: &HashMap<String, String>) -> ProviderCommand {
    let executable = provider_executable(
        environment
            .get("REA_RIZIN_COMMAND")
            .cloned()
            .unwrap_or_else(|| "rizin".to_owned()),
        environment,
    );
    let command = input
        .get("command")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let path = input
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or_default();
    ProviderCommand {
        executable,
        arguments: vec![
            "-N".to_owned(),
            "-q".to_owned(),
            "-e".to_owned(),
            "scr.color=0".to_owned(),
            "-c".to_owned(),
            command,
            absolute_caller_path(path),
        ],
        identity: rizin_identity(),
        environment_overrides: Vec::new(),
    }
}

/// `objdumpCommand(input)`.
fn objdump_arguments(input: &Value) -> Vec<String> {
    let operation = input
        .get("operation")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if operation == "architectures" {
        return vec!["-i".to_owned()];
    }
    let follow = input
        .get("follow_debug_links")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let path = input
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let mut arguments: Vec<String> = match operation {
        "file_headers" => vec!["-f".to_owned()],
        "section_headers" => vec!["-h".to_owned()],
        "symbols" => vec!["-t".to_owned()],
        "relocations" => vec!["-r".to_owned()],
        "dwarf" => vec![
            "-W".to_owned(),
            if follow { "-WK" } else { "-WN" }.to_owned(),
        ],
        "disassemble" => match input.get("symbol").and_then(Value::as_str) {
            Some(symbol) => vec![format!("--disassemble={symbol}")],
            None => vec!["-d".to_owned()],
        },
        "disassemble_all" => vec!["-D".to_owned()],
        // The schema restricts `operation`; preserve a stable default otherwise.
        _ => vec!["-d".to_owned()],
    };
    arguments.push(absolute_caller_path(path));
    arguments
}

/// `providerExecutable(executable, environment, platform)`.
fn provider_executable(executable: String, environment: &HashMap<String, String>) -> String {
    if cfg!(windows) {
        resolve_windows_provider_executable(&executable, environment)
    } else {
        executable
    }
}

/// `absoluteCallerPath(path)` for the host platform.
pub fn absolute_caller_path(path: &str) -> String {
    if cfg!(windows) {
        windows_resolve(&current_dir(), path)
    } else {
        posix_absolute(path, &current_dir())
    }
}

fn current_dir() -> String {
    std::env::current_dir()
        .map(|dir| dir.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// POSIX `absoluteCallerPath`: keep every `..` for the filesystem to resolve,
/// drop interior `.` and empty segments, and preserve one trailing separator.
fn posix_absolute(path: &str, cwd: &str) -> String {
    if !path.starts_with('/') {
        let base = if cwd.starts_with('/') {
            cwd.to_owned()
        } else {
            posix_absolute(cwd, "/")
        };
        return posix_absolute(&format!("{base}/{path}"), "/");
    }
    let segments: Vec<&str> = path
        .split('/')
        .filter(|segment| !segment.is_empty() && *segment != ".")
        .collect();
    let directory = trailing_directory(path) && !segments.is_empty();
    format!(
        "/{}{}",
        segments.join("/"),
        if directory { "/" } else { "" }
    )
}

/// True when the path ends with `/` or `/.` (the `/\.?$/u` test).
fn trailing_directory(path: &str) -> bool {
    path.ends_with('/') || path.ends_with("/.")
}

// Windows path handling mirrors Node's `path.win32`. It cannot be exercised on
// this host, so it stays deliberately small and literal.
#[cfg(windows)]
fn windows_resolve(cwd: &str, path: &str) -> String {
    use std::path::Path;
    if windows_is_absolute(path) {
        windows_normalize(path)
    } else {
        windows_normalize(&format!("{}\\{}", cwd.trim_end_matches(['\\', '/']), path))
    }
}

#[cfg(not(windows))]
fn windows_resolve(cwd: &str, path: &str) -> String {
    // Never selected off Windows; kept for a single definition site.
    let _ = cwd;
    path.to_owned()
}

#[cfg(windows)]
fn windows_is_absolute(path: &str) -> bool {
    let bytes = path.as_bytes();
    match bytes.first() {
        Some(b'/' | b'\\') => true,
        Some(letter) if letter.is_ascii_alphabetic() => {
            bytes.get(1) == Some(&b':') && matches!(bytes.get(2), Some(b'/' | b'\\'))
        }
        _ => false,
    }
}

#[cfg(windows)]
fn windows_normalize(path: &str) -> String {
    let mut root = String::new();
    let mut rest = path;
    let bytes = path.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        root = format!("{}:\\", (bytes[0] as char).to_ascii_uppercase());
        rest = &path[2..];
    } else if matches!(bytes.first(), Some(b'/' | b'\\')) {
        root = "\\".to_owned();
    }
    let mut stack: Vec<&str> = Vec::new();
    for segment in rest.split(['/', '\\']) {
        match segment {
            "" | "." => {}
            ".." => {
                stack.pop();
            }
            other => stack.push(other),
        }
    }
    format!("{root}{}", stack.join("\\"))
}

/// `resolveWindowsProviderExecutable(executable, environment)`.
#[cfg(windows)]
pub fn resolve_windows_provider_executable(
    executable: &str,
    environment: &HashMap<String, String>,
) -> String {
    let cwd = current_dir();
    let absolute = |relative: &str| windows_resolve(&cwd, relative);
    if windows_is_absolute(executable)
        || executable.contains('/')
        || executable.contains('\\')
        || windows_has_root(executable)
    {
        return absolute(executable);
    }
    let Some(path_value) = environment
        .get("PATH")
        .or_else(|| environment.get("Path"))
        .or_else(|| environment.get("path"))
    else {
        return executable.to_owned();
    };
    let entries = split_windows_path(path_value);
    let explicit = windows_extension(executable).to_ascii_lowercase();
    if !explicit.is_empty() && explicit != ".com" && explicit != ".exe" {
        return executable.to_owned();
    }
    let extensions: Vec<String> = if !explicit.is_empty() {
        vec![String::new()]
    } else {
        environment
            .get("PATHEXT")
            .or_else(|| environment.get("PathExt"))
            .cloned()
            .unwrap_or_else(|| ".COM;.EXE".to_owned())
            .split(';')
            .filter(|extension| {
                let lower = extension.to_ascii_lowercase();
                lower == ".com" || lower == ".exe"
            })
            .map(str::to_owned)
            .collect()
    };
    for entry in entries {
        if entry.is_empty() {
            continue;
        }
        for extension in &extensions {
            let candidate = windows_resolve(&cwd, &format!("{entry}\\{executable}{extension}"));
            if is_regular_file(&candidate) {
                return candidate;
            }
        }
    }
    executable.to_owned()
}

#[cfg(not(windows))]
pub fn resolve_windows_provider_executable(
    executable: &str,
    _environment: &HashMap<String, String>,
) -> String {
    executable.to_owned()
}

#[cfg(windows)]
fn windows_has_root(executable: &str) -> bool {
    let bytes = executable.as_bytes();
    matches!(bytes.first(), Some(b'/' | b'\\'))
        || (bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':')
}

#[cfg(windows)]
fn windows_extension(name: &str) -> String {
    match name.rfind('.') {
        Some(index) if index > 0 => name[index..].to_owned(),
        _ => String::new(),
    }
}

#[cfg(windows)]
fn is_regular_file(path: &str) -> bool {
    std::fs::metadata(path)
        .map(|info| info.is_file())
        .unwrap_or(false)
}

/// `splitWindowsPath(value)`: split on unquoted `;`, then strip paired quotes.
#[cfg(windows)]
fn split_windows_path(value: &str) -> Vec<String> {
    let mut entries: Vec<String> = Vec::new();
    let mut start = 0usize;
    let mut quoted = false;
    let bytes = value.as_bytes();
    for index in 0..bytes.len() {
        if bytes[index] == b'"' {
            quoted = !quoted;
        } else if bytes[index] == b';' && !quoted {
            entries.push(value[start..index].to_owned());
            start = index + 1;
        }
    }
    entries.push(value[start..].to_owned());
    entries
        .into_iter()
        .filter_map(|entry| {
            if entry.len() >= 2 && entry.starts_with('"') && entry.ends_with('"') {
                Some(entry[1..entry.len() - 1].to_owned())
            } else if entry.contains('"') {
                None
            } else {
                Some(entry)
            }
        })
        .collect()
}
