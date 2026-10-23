#![cfg(unix)]

use serde_json::Value;
use std::{fs, process::Command};
use tempfile::tempdir;

#[test]
fn inspect_nib_archive_returns_decoded_objects_with_source_identity() {
    let directory = tempdir().expect("temporary directory");
    let path = directory.path().join("Main.nib");
    fs::write(&path, minimal_nib_archive()).expect("write NIB archive");

    let output = Command::new(env!("CARGO_BIN_EXE_rea-native"))
        .args([
            "inspect-nib-archive",
            path.to_str().expect("temporary path is UTF-8"),
            "--format",
            "json",
        ])
        .output()
        .expect("run native CLI");
    let evidence: Value = serde_json::from_slice(&output.stdout).expect("JSON output");

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(evidence["operation"], "inspect_nib_archive");
    assert_eq!(evidence["subject"]["format"], "nib");
    assert_eq!(
        evidence["subject"]["local_path"],
        path.to_string_lossy().as_ref()
    );
    assert_eq!(
        evidence["normalized_result"]["objects"][0]["class_name"],
        "Outlet"
    );
}

#[test]
fn inspect_nib_archive_preserves_malformed_input_reason() {
    let directory = tempdir().expect("temporary directory");
    let path = directory.path().join("bad.nib");
    fs::write(&path, b"NIBArchive\0").expect("write malformed NIB archive");

    let output = Command::new(env!("CARGO_BIN_EXE_rea-native"))
        .args([
            "inspect-nib-archive",
            path.to_str().expect("temporary path is UTF-8"),
            "--format",
            "json",
        ])
        .output()
        .expect("run native CLI");
    let failure: Value = serde_json::from_slice(&output.stdout).expect("JSON failure");

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(failure["code"], "parse_failed");
    assert_eq!(failure["details"]["operation"], "inspect_nib_archive");
    assert!(failure["details"]["reason"].is_string());
}

fn minimal_nib_archive() -> Vec<u8> {
    let mut bytes = vec![0u8; 50];
    bytes[..10].copy_from_slice(b"NIBArchive");
    put_u32(&mut bytes, 10, 1);
    put_u32(&mut bytes, 14, 7);
    put_u32(&mut bytes, 18, 1);
    put_u32(&mut bytes, 22, 50);
    put_u32(&mut bytes, 26, 1);
    put_u32(&mut bytes, 30, 53);
    put_u32(&mut bytes, 34, 1);
    put_u32(&mut bytes, 38, 59);
    put_u32(&mut bytes, 42, 1);
    put_u32(&mut bytes, 46, 65);
    bytes.extend_from_slice(&[0x80, 0x80, 0x81]);
    bytes.extend_from_slice(&[0x85, b't', b'i', b't', b'l', b'e']);
    bytes.extend_from_slice(&[0x80, 8, 0x83, b'a', b'b', b'c']);
    bytes.extend_from_slice(&[0x86, 0x80, b'O', b'u', b't', b'l', b'e', b't']);
    bytes
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
