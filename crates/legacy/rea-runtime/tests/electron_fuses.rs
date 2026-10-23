#![cfg(unix)]

use std::{fs, process::Command};

fn fixture() -> Vec<u8> {
    let mut bytes = vec![0; 64];
    bytes[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
    bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
    bytes.extend_from_slice(b"dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX");
    bytes.extend([1, 6, 0x31, 0x30, 0x72, 0x31, 0x31, 0x30]);
    bytes
}

#[test]
fn cli_reports_fuses_from_a_supported_elf_target() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("electron");
    fs::write(&path, fixture()).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_rea-native"))
        .args([
            "inspect-electron-fuses",
            path.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let evidence: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(evidence["operation"], "inspect_electron_fuses");
    assert_eq!(evidence["normalized_result"]["artifact"]["format"], "elf");
    assert_eq!(
        evidence["normalized_result"]["slices"][0]["sentinels"][0]["fuses"][0]["state"],
        "enabled"
    );
    assert_eq!(evidence["locations"][0]["path"], path.to_str().unwrap());
}
