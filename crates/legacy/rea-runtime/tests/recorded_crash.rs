#![cfg(unix)]

use serde_json::Value;
use std::{fs, process::Command};

fn elf_core_header(machine: u16) -> Vec<u8> {
    let mut bytes = vec![0; 64];
    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[16..18].copy_from_slice(&4u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&machine.to_le_bytes());
    bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
    bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
    bytes
}

fn run(path: &std::path::Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_rea-native"))
        .args([
            "inspect-recorded-crash",
            path.to_str().expect("fixture path is UTF-8"),
            "--format",
            "json",
        ])
        .output()
        .expect("native command should start")
}

#[test]
fn cli_reports_amd64_core_evidence_without_running_a_target() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("core.amd64");
    fs::write(&path, elf_core_header(62)).unwrap();

    let output = run(&path);
    assert!(output.status.success(), "{output:?}");
    let evidence: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(evidence["operation"], "inspect_recorded_crash");
    assert_eq!(evidence["subject"]["format"], "elf");
    assert_eq!(
        evidence["normalized_result"]["architecture"],
        "x86_64-little-endian"
    );
    assert_eq!(
        evidence["normalized_result"]["limitations"][0],
        "Historical process identity, current file identity, note coverage and signal-thread association remain unknown."
    );
}

#[test]
fn cli_reports_aarch64_core_evidence() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("core.aarch64");
    fs::write(&path, elf_core_header(183)).unwrap();

    let output = run(&path);
    assert!(output.status.success(), "{output:?}");
    let evidence: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        evidence["normalized_result"]["architecture"],
        "aarch64-little-endian"
    );
    assert_eq!(evidence["subject"]["architecture"], "arm64");
}

#[test]
fn cli_rejects_malformed_core_with_error_envelope() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("malformed.core");
    fs::write(&path, b"not an ELF core").unwrap();

    let output = run(&path);
    assert!(!output.status.success(), "{output:?}");
    let error: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(error["code"], "invalid_request");
    assert_eq!(error["category"], "invalid_format");
    assert_eq!(error["details"]["operation"], "inspect_recorded_crash");
}
