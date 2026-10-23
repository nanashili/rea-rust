#![cfg(unix)]

use serde_json::Value;
use std::{fs, process::Command};
use tempfile::tempdir;

#[test]
fn decode_interface_builder_decodes_archives_and_reports_coverage() {
    let bundle = tempdir().expect("temporary app bundle");
    let nib = bundle.path().join("Contents/Resources/Main.nib");
    fs::create_dir_all(nib.parent().expect("nib parent")).expect("create bundle resources");
    fs::write(
        &nib,
        br#"<?xml version="1.0"?><plist version="1.0"><dict><key>com.apple.ibtool.document.objects</key><dict><key>root</key><dict><key>customClass</key><string>NSView</string><key>label</key><string>Main View</string></dict></dict></dict></plist>"#,
    )
    .expect("write Interface Builder archive");

    let output = Command::new(env!("CARGO_BIN_EXE_rea-native"))
        .args([
            "decode-interface-builder",
            bundle.path().to_str().expect("bundle path is UTF-8"),
            &"a".repeat(64),
            "--max-documents",
            "1",
            "--max-objects",
            "4",
            "--max-connections",
            "3",
            "--format",
            "json",
        ])
        .output()
        .expect("run native CLI");
    let evidence: Value = serde_json::from_slice(&output.stdout).expect("JSON output");
    let report = &evidence["normalized_result"];

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(evidence["operation"], "decode_interface_builder");
    assert_eq!(evidence["subject"]["format"], "directory");
    assert_eq!(evidence["subject"]["digest"]["sha256"], "a".repeat(64));
    assert_eq!(evidence["parameters"]["max_documents"], 1);
    assert_eq!(evidence["parameters"]["max_objects"], 4);
    assert_eq!(evidence["parameters"]["max_connections"], 3);
    assert_eq!(report["target_sha256"], "a".repeat(64));
    assert_eq!(
        report["documents"][0]["relative_path"],
        "Contents/Resources/Main.nib"
    );
    assert!(
        report["graph"]["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|node| node["name"] == "Main View")
    );
}

#[test]
fn decode_interface_builder_rejects_invalid_target_digest() {
    let bundle = tempdir().expect("temporary app bundle");
    let output = Command::new(env!("CARGO_BIN_EXE_rea-native"))
        .args([
            "decode-interface-builder",
            bundle.path().to_str().expect("bundle path is UTF-8"),
            "not-a-sha256",
            "--format",
            "json",
        ])
        .output()
        .expect("run native CLI");
    let failure: Value = serde_json::from_slice(&output.stdout).expect("JSON failure");

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(failure["code"], "invalid_request");
    assert_eq!(failure["details"]["operation"], "decode_interface_builder");
}
