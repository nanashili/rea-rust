//! Windows `.bat`/`.cmd` invocation through an explicit cmd.exe.
//!
//! Compatibility owner: `src/process/WindowsBatchCommand.ts`. Node rejects
//! batch files without a shell (CVE-2024-27980); this builds an explicit,
//! non-AutoRun cmd.exe command line and rejects any token cmd.exe could
//! expand, split or redirect. Active only on Windows.
#![cfg_attr(not(windows), allow(dead_code))]

use std::collections::HashMap;

/// Why a batch launcher cannot be passed safely to cmd.exe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BatchFailure {
    InvalidComSpec,
    Metacharacter,
}

/// A batch-invocation error with the original caller-visible message.
#[derive(Clone, Debug)]
pub struct BatchError {
    pub reason: BatchFailure,
    pub message: String,
}

/// Exact executable and verbatim argv for shell-free process creation.
#[derive(Clone, Debug)]
pub struct BatchCommand {
    pub command: String,
    pub arguments: Vec<String>,
}

/// `isWindowsBatchFile`: `.bat`/`.cmd`, case-insensitive.
pub fn is_windows_batch_file(command: &str) -> bool {
    let lower = command.to_ascii_lowercase();
    lower.ends_with(".bat") || lower.ends_with(".cmd")
}

/// `quoteWindowsBatchToken`.
fn quote_token(value: &str) -> Result<String, BatchError> {
    if value.is_empty()
        || value.contains('\0')
        || value.contains('\r')
        || value.contains('\n')
        || value
            .chars()
            .any(|c| matches!(c, '"' | '%' | '^' | '!' | '&' | '|' | '<' | '>'))
    {
        return Err(BatchError {
            reason: BatchFailure::Metacharacter,
            message: "Windows batch arguments cannot contain command-interpreter metacharacters"
                .into(),
        });
    }
    Ok(format!("\"{value}\""))
}

fn win32_basename(path: &str) -> &str {
    let trimmed = path.trim_end_matches(['\\', '/']);
    match trimmed.rfind(['\\', '/']) {
        Some(index) => &trimmed[index + 1..],
        None => trimmed,
    }
}

fn win32_is_absolute(path: &str) -> bool {
    let bytes = path.as_bytes();
    match bytes.first() {
        Some(b'/' | b'\\') => true,
        Some(letter) if letter.is_ascii_alphabetic() => {
            bytes.get(1) == Some(&b':') && matches!(bytes.get(2), Some(b'/' | b'\\'))
        }
        _ => false,
    }
}

fn env_lookup<'a>(environment: &'a HashMap<String, String>, key: &str) -> Option<&'a str> {
    environment
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(key))
        .map(|(_, value)| value.as_str())
}

/// `windowsBatchCommand`.
pub fn windows_batch_command(
    environment: &HashMap<String, String>,
    batch_path: &str,
    arguments: &[String],
) -> Result<BatchCommand, BatchError> {
    let system_root = env_lookup(environment, "SYSTEMROOT");
    let com_spec = env_lookup(environment, "COMSPEC")
        .map(str::to_owned)
        .unwrap_or_else(|| match system_root {
            None => "C:\\Windows\\System32\\cmd.exe".to_owned(),
            Some(root) => format!("{}\\System32\\cmd.exe", root.trim_end_matches(['\\', '/'])),
        });
    if !win32_is_absolute(&com_spec) || win32_basename(&com_spec).to_ascii_lowercase() != "cmd.exe"
    {
        return Err(BatchError {
            reason: BatchFailure::InvalidComSpec,
            message: "Windows ComSpec must be an absolute cmd.exe path".into(),
        });
    }
    let mut tokens = Vec::with_capacity(arguments.len() + 1);
    tokens.push(quote_token(batch_path)?);
    for argument in arguments {
        tokens.push(quote_token(argument)?);
    }
    Ok(BatchCommand {
        command: com_spec,
        arguments: vec![
            "/d".into(),
            "/e:on".into(),
            "/v:off".into(),
            "/s".into(),
            "/c".into(),
            format!("\"{}\"", tokens.join(" ")),
        ],
    })
}
