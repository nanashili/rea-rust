#![cfg(unix)]

use serde_json::{Value, json};
use std::{fs, process::Command};
use tempfile::tempdir;

fn minimal_apk() -> Vec<u8> {
    let entry_name = b"AndroidManifest.xml";
    let manifest = b"<manifest package=\"example.test\"/>";
    let mut bytes = vec![0; 30];

    bytes[..4].copy_from_slice(b"PK\x03\x04");
    bytes[18..22].copy_from_slice(&(manifest.len() as u32).to_le_bytes());
    bytes[22..26].copy_from_slice(&(manifest.len() as u32).to_le_bytes());
    bytes[26..28].copy_from_slice(&(entry_name.len() as u16).to_le_bytes());
    bytes[28..30].copy_from_slice(&0_u16.to_le_bytes());
    bytes.extend_from_slice(entry_name);
    bytes.extend_from_slice(manifest);

    bytes
}

fn write_input(directory: &std::path::Path, input: &Value) -> std::path::PathBuf {
    let path = directory.join("input.json");
    fs::write(&path, serde_json::to_vec(input).unwrap()).unwrap();
    path
}

#[test]
fn search_android_classes_preserves_empty_query_and_caller_path() {
    let directory = tempdir().unwrap();
    let apk_path = directory.path().join("empty.apk");
    fs::write(&apk_path, minimal_apk()).unwrap();
    let input_path = write_input(
        directory.path(),
        &json!({
            "path": apk_path.to_string_lossy(),
            "query": "",
        }),
    );

    let output = Command::new(env!("CARGO_BIN_EXE_rea-native"))
        .args([
            "search-android-classes",
            input_path.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    let evidence: Value = serde_json::from_slice(&output.stdout).unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(evidence["operation"], "search_android_classes");
    assert_eq!(
        evidence["parameters"]["path"],
        apk_path.to_string_lossy().as_ref()
    );
    assert_eq!(evidence["parameters"]["query"], "");
    assert_eq!(evidence["normalized_result"]["query"], "");
    assert_eq!(evidence["normalized_result"]["total_classes"], 0);
    assert_eq!(evidence["normalized_result"]["coverage"], "complete");
}

#[test]
fn trace_android_references_reports_missing_class_in_issue_details() {
    let directory = tempdir().unwrap();
    let apk_path = directory.path().join("empty.apk");
    fs::write(&apk_path, minimal_apk()).unwrap();
    let input_path = write_input(
        directory.path(),
        &json!({
            "path": apk_path.to_string_lossy(),
            "class_name": "example.test.Missing",
        }),
    );

    let output = Command::new(env!("CARGO_BIN_EXE_rea-native"))
        .args([
            "trace-android-references",
            input_path.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    let failure: Value = serde_json::from_slice(&output.stdout).unwrap();

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(failure["code"], "invalid_request");
    assert_eq!(failure["category"], "invalid_input");
    assert_eq!(failure["details"]["operation"], "trace_android_references");
    assert!(
        failure["details"]["issues"][0]["message"]
            .as_str()
            .unwrap()
            .contains("was not found")
    );
}

#[test]
fn android_class_search_rejects_unknown_input_fields_with_operation_context() {
    let directory = tempdir().unwrap();
    let input_path = write_input(
        directory.path(),
        &json!({
            "path": directory.path().join("empty.apk").to_string_lossy(),
            "query": "",
            "unexpected": true,
        }),
    );

    let output = Command::new(env!("CARGO_BIN_EXE_rea-native"))
        .args([
            "search-android-classes",
            input_path.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    let failure: Value = serde_json::from_slice(&output.stdout).unwrap();

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(failure["code"], "invalid_request");
    assert_eq!(failure["category"], "invalid_input");
    assert_eq!(failure["details"]["operation"], "search_android_classes");
    assert_eq!(
        failure["details"]["issues"][0]["reason"],
        "unrecognized_keys"
    );
}
