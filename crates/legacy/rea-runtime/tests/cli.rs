#![cfg(unix)]
//! Real standalone command boundary: file admission, Evidence and exit behavior.
use rea_core::canonical_json;
use serde_json::Value;
use std::{
    ffi::OsString,
    fs,
    os::{
        fd::OwnedFd,
        unix::{ffi::OsStringExt, fs::PermissionsExt, net::UnixStream},
    },
    process::{Command, Output, Stdio},
};

fn fixture() -> Vec<u8> {
    let mut bytes = vec![0; 64];
    bytes[..7].copy_from_slice(&[127, 69, 76, 70, 2, 1, 1]);
    bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
    bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
    bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
    bytes
}

fn web_capture_snapshot(script_hash: &str) -> Value {
    serde_json::json!({
        "inspection": {
            "target": {"target_id": "page", "url": "https://example.test/"},
            "dom": {"nodes": [], "total_nodes": 0},
            "frames": [],
            "scripts": {"items": [{"script_key": "script", "cdp_hash": script_hash}], "total": 1},
            "resources": [],
            "network": {"requests": [], "websocket_connections": []},
            "metadata": {"responses": [], "dom_urls": [], "agent_hints": []},
            "accessibility": {"nodes": [], "total_nodes": 0},
            "storage": {"local_storage_keys": [], "session_storage_keys": [], "indexed_db_names": [], "cache_names": [], "content_fingerprints": [], "fingerprints_complete": true, "usage_bytes": 0, "quota_bytes": 1},
            "completeness": {"policy_filtered_sections": [], "attach_limited_sections": [], "truncated_sections": [], "unavailable_sections": []}
        }
    })
}

fn pe_target_fixture() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x2000];
    bytes[0..2].copy_from_slice(b"MZ");
    bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    bytes[0x84..0x86].copy_from_slice(&0x014cu16.to_le_bytes());
    bytes[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
    bytes[0x94..0x96].copy_from_slice(&0xe0u16.to_le_bytes());
    bytes[0x96..0x98].copy_from_slice(&2u16.to_le_bytes());
    bytes[0x98..0x9a].copy_from_slice(&0x10bu16.to_le_bytes());
    bytes[0xd4..0xd8].copy_from_slice(&0x200u32.to_le_bytes());
    bytes[0xf4..0xf8].copy_from_slice(&7u32.to_le_bytes());
    bytes[0x178..0x180].copy_from_slice(b".text\0\0\0");
    bytes[0x184..0x188].copy_from_slice(&0x1000u32.to_le_bytes());
    bytes[0x188..0x18c].copy_from_slice(&0x1800u32.to_le_bytes());
    bytes[0x18c..0x190].copy_from_slice(&0x200u32.to_le_bytes());
    bytes[0x190..0x194].copy_from_slice(&0x200u32.to_le_bytes());
    bytes
}

#[test]
fn cli_help_advertises_plist_inspection() {
    let output = Command::new(env!("CARGO_BIN_EXE_rea-native"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("inspect-plist PATH --format json"));
}

#[test]
fn cli_inspects_keyed_archive_with_selected_root_and_object_page() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("archive.plist");
    fs::write(
        &path,
        br#"<?xml version="1.0"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist><dict>
<key>$archiver</key><string>NSKeyedArchiver</string>
<key>$objects</key><array><string>$null</string><string>Hello</string></array>
<key>$top</key><dict><key>root</key><dict><key>CF$UID</key><integer>1</integer></dict></dict>
</dict></plist>"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_rea-native"))
        .args([
            "inspect-keyed-archive",
            path.to_str().unwrap(),
            "--root",
            "root",
            "--offset",
            "1",
            "--limit",
            "1",
            "--json",
        ])
        .output()
        .unwrap();

    assert!(output.status.success(), "{output:?}");
    let evidence = json(&output);
    assert_eq!(evidence["operation"], "inspect_keyed_archive");
    assert_eq!(
        evidence["normalized_result"]["roots"]["root"],
        serde_json::json!({"CF$UID": 1})
    );
    assert_eq!(evidence["normalized_result"]["objects"][0]["id"], 1);
    assert_eq!(
        evidence["normalized_result"]["next_offset"],
        serde_json::Value::Null
    );
    directory.close().unwrap();
}

#[test]
fn cli_inspects_apktool_client_with_selected_launcher() {
    let directory = tempfile::tempdir().unwrap();
    let launcher = directory.path().join("apktool");
    fs::write(&launcher, "#!/bin/sh\nprintf '2.9.3-dirty\\n'\n").unwrap();
    let mut permissions = fs::metadata(&launcher).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&launcher, permissions).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_rea-native"))
        .args(["inspect-apktool-client", "--format", "json"])
        .env("REA_APKTOOL_COMMAND", &launcher)
        .output()
        .unwrap();

    assert!(output.status.success(), "{output:?}");
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["client"]["command"], launcher.to_str().unwrap());
    assert_eq!(result["client"]["command_source"], "environment");
    assert_eq!(result["client"]["apktool_version"], "2.9.3-dirty");
}

#[test]
fn cli_help_advertises_android_package_inspection() {
    let output = Command::new(env!("CARGO_BIN_EXE_rea-native"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("inspect-android-package PATH --format json")
    );
}

#[test]
fn cli_help_advertises_pe_target_inspection() {
    let output = Command::new(env!("CARGO_BIN_EXE_rea-native"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("inspect-pe-target PATH --format json")
    );
}

#[test]
fn cli_inspects_pe_target_and_returns_evidence() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("target.exe");
    fs::write(&path, pe_target_fixture()).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_rea-native"))
        .args([
            "inspect-pe-target",
            path.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .unwrap();

    assert!(output.status.success(), "{output:?}");
    let evidence: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(evidence["operation"], "inspect_pe_target");
    assert_eq!(evidence["subject"]["format"], "pe");
    assert_eq!(evidence["normalized_result"]["format"], "pe");
}

#[test]
fn cli_rejects_malformed_pe_target_with_error_envelope() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("malformed.exe");
    fs::write(&path, b"MZ").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_rea-native"))
        .args([
            "inspect-pe-target",
            path.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let error: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(error["code"], "invalid_request");
    assert_eq!(error["details"]["operation"], "inspect_pe_target");
    assert_eq!(error["details"]["issues"][0]["reason"], "invalid_format");
}

#[test]
fn cli_help_advertises_process_observation() {
    let output = Command::new(env!("CARGO_BIN_EXE_rea-native"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("inspect-process-observation INPUT --format json")
    );
}

#[test]
fn cli_help_advertises_evm_interface_inspection() {
    let output = Command::new(env!("CARGO_BIN_EXE_rea-native"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("inspect-evm-interface INPUT --format json")
    );
}

#[test]
fn cli_rejects_unknown_evm_encoding_before_reading_a_carrier() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("request.json");
    fs::write(
        &input,
        r#"{"path":"/tmp/does-not-need-to-exist","encoding":"base64"}"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_rea-native"))
        .args([
            "inspect-evm-interface",
            input.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let error: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(error["code"], "invalid_request");
    assert_eq!(error["details"]["operation"], "inspect_evm_interface");
    assert_eq!(error["details"]["issues"][0]["path"][0], "encoding");
    assert_eq!(error["details"]["issues"][0]["reason"], "invalid_value");
}

#[test]
fn cli_help_advertises_electron_fuse_inspection() {
    let output = Command::new(env!("CARGO_BIN_EXE_rea-native"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("inspect-electron-fuses PATH --format json")
    );
}

#[test]
fn cli_help_advertises_recorded_crash_inspection() {
    let output = Command::new(env!("CARGO_BIN_EXE_rea-native"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("inspect-recorded-crash PATH --format json")
    );
}

#[test]
fn cli_help_advertises_revert_evidence_inspection() {
    let output = Command::new(env!("CARGO_BIN_EXE_rea-native"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("inspect-revert-evidence INPUT --format json")
    );
}

#[test]
fn cli_help_advertises_macho_inspection() {
    let output = Command::new(env!("CARGO_BIN_EXE_rea-native"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("inspect-macho PATH --format json"));
}

#[test]
fn cli_help_describes_the_selected_asset_catalog_target() {
    let output = Command::new(env!("CARGO_BIN_EXE_rea-native"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("inspect-asset-catalog TARGET_PATH TARGET_SHA256")
    );
}

#[test]
fn cli_asset_catalog_rejects_duplicate_page_options() {
    let digest = "a".repeat(64);
    let output = Command::new(env!("CARGO_BIN_EXE_rea-native"))
        .args([
            "inspect-asset-catalog",
            "/tmp/Demo.app/Contents/MacOS/Demo",
            digest.as_str(),
            "--offset",
            "1",
            "--offset",
            "2",
            "--format",
            "json",
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let failure = json(&output);
    assert_eq!(failure["code"], "invalid_request");
    assert!(
        failure["details"]["issues"][0]["message"]
            .as_str()
            .unwrap()
            .contains("may only be provided once")
    );
}

#[test]
fn cli_help_advertises_binary_layout_inspection() {
    let output = Command::new(env!("CARGO_BIN_EXE_rea-native"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("inspect-binary-layout PATH --format json")
    );
}

#[test]
fn cli_help_advertises_managed_artifact_inspection() {
    let output = Command::new(env!("CARGO_BIN_EXE_rea-native"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("inspect-managed-artifact PATH --format json")
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("inspect-managed-members INPUT --format json")
    );
}

#[test]
fn cli_help_advertises_android_and_managed_boundary_inspections() {
    let output = Command::new(env!("CARGO_BIN_EXE_rea-native"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());

    let help = String::from_utf8_lossy(&output.stdout);
    assert!(help.contains("inspect-managed-native-boundaries PATH --format json"));
    assert!(help.contains("inspect-android-class INPUT --format json"));
    assert!(help.contains("inspect-android-method INPUT --format json"));
    assert!(help.contains("search-android-classes INPUT --format json"));
    assert!(help.contains("trace-android-references INPUT --format json"));
    assert!(help.contains("inspect-android-resource INPUT --format json"));
    assert!(help.contains("inspect-android-manifest-component INPUT --format json"));
}

#[test]
fn cli_help_advertises_wasm_interface_comparison() {
    let output = Command::new(env!("CARGO_BIN_EXE_rea-native"))
        .arg("--help")
        .output()
        .unwrap();

    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("compare-wasm-interfaces INPUT --format json"));
}

#[test]
fn cli_help_advertises_web_capture_comparison() {
    let output = Command::new(env!("CARGO_BIN_EXE_rea-native"))
        .arg("--help")
        .output()
        .unwrap();

    assert!(output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("compare-web-captures BEFORE_JSON AFTER_JSON --format json")
    );
}

#[test]
fn cli_compares_web_captures_and_returns_only_the_computed_result() {
    let before = serde_json::to_string(&web_capture_snapshot("before")).unwrap();
    let after = serde_json::to_string(&web_capture_snapshot("after")).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_rea-native"))
        .args(["compare-web-captures", &before, &after, "--json"])
        .output()
        .unwrap();

    assert!(output.status.success(), "{output:?}");
    let result = json(&output);
    assert_eq!(result["overall_status"], "changed");
    assert_eq!(result["dimensions"]["scripts"]["status"], "changed");
    assert!(result.get("evidence_id").is_none());
}

#[test]
fn cli_accepts_web_capture_json_files() {
    let directory = tempfile::tempdir().unwrap();
    let before_path = directory.path().join("before.json");
    let after_path = directory.path().join("after.json");
    fs::write(
        &before_path,
        serde_json::to_vec(&web_capture_snapshot("before")).unwrap(),
    )
    .unwrap();
    fs::write(
        &after_path,
        serde_json::to_vec(&web_capture_snapshot("before")).unwrap(),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_rea-native"))
        .args([
            "compare-web-captures",
            before_path.to_str().unwrap(),
            after_path.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .unwrap();

    assert!(output.status.success(), "{output:?}");
    assert_eq!(json(&output)["overall_status"], "unchanged");
}

#[test]
fn cli_reports_tagged_web_capture_input_failures() {
    let output = Command::new(env!("CARGO_BIN_EXE_rea-native"))
        .args(["compare-web-captures", "{}", "{}", "--json"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let failure = json(&output);
    assert_eq!(failure["error"], "Analysis failed");
    assert_eq!(failure["code"], "invalid_request");
    assert_eq!(failure["category"], "invalid_input");
    assert_eq!(failure["details"]["operation"], "compare_web_captures");
}
fn inspect(path: &std::path::Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rea-native"))
        .arg("inspect-rust-binary")
        .arg(path)
        .args(["--format", "json"])
        .output()
        .unwrap()
}
fn json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap()
}
fn bundle_for(record: &Value) -> Value {
    bundle_with_unknowns(record, Vec::new())
}
fn bundle_with_unknowns(record: &Value, unknowns: Vec<Value>) -> Value {
    serde_json::json!({
        "artifacts": [{
            "digest": record["subject"]["digest"],
            "format": record["subject"]["format"],
            "architecture": record["subject"]["architecture"],
        }],
        "providers": [record["provider"]],
        "environments": [],
        "scenarios": [],
        "captures": [],
        "unknowns": unknowns,
        "records": [record],
    })
}
fn unknown_revision(
    evidence_id: &Value,
    revision: u64,
    previous_revision_digest: Option<&str>,
    status: &str,
) -> Value {
    let identity = serde_json::json!({
        "domain": "comparison-test",
        "question": "Which bundle revision is current?",
        "scope_digest": null,
    });
    let identity = serde_json::value::to_raw_value(&identity).unwrap();
    let unknown_id = format!("unk_{}", canonical_json::digest_raw(&identity).unwrap());
    let mut unknown = serde_json::json!({
        "unknown_id": unknown_id,
        "revision": revision,
        "previous_revision_digest": previous_revision_digest,
        "scope_digest": null,
        "question": "Which bundle revision is current?",
        "status": status,
        "severity": "medium",
        "domain": "comparison-test",
        "supporting_evidence_ids": [],
        "contradicting_evidence_ids": [],
        "required_authority": null,
        "required_confidence": "inferred",
        "required_environment": null,
        "recommended_probes": [],
        "relationships": [],
        "resolution": null,
        "mutation_evidence_ids": [evidence_id],
    });
    let unsigned = serde_json::value::to_raw_value(&unknown).unwrap();
    unknown["revision_digest"] = Value::String(canonical_json::digest_raw(&unsigned).unwrap());
    unknown
}
fn export(source: &std::path::Path, output: &std::path::Path, options: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rea-native"))
        .arg("evidence-export")
        .arg(source)
        .arg(output)
        .args(options)
        .args(["--format", "json"])
        .output()
        .unwrap()
}
fn compare(left: &std::path::Path, right: &std::path::Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rea-native"))
        .arg("compare")
        .arg(left)
        .arg(right)
        .args(["--format", "json"])
        .output()
        .unwrap()
}

#[test]
fn standalone_inspection_emits_complete_artifact_bound_evidence() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("example");
    fs::write(&path, fixture()).unwrap();
    let output = inspect(&path);
    assert!(output.status.success(), "{:?}", output);
    assert!(output.stderr.is_empty());
    let evidence = json(&output);
    assert_eq!(evidence["operation"], "inspect_rust_binary");
    assert_eq!(evidence["subject"]["local_path"], path.to_str().unwrap());
    assert_eq!(
        evidence["subject"]["digest"]["sha256"],
        "40abde8b8e31245547642e73c243d35f3cc3c8d89941a1d0e469d3097cd07594"
    );
    assert_eq!(evidence["subject"]["architecture"], "x86_64");
    assert_eq!(evidence["normalized_result"]["architecture"], "amd64");
    assert_eq!(evidence["normalized_result"]["artifact"]["bytes"], 64);
    assert!(evidence["normalized_result"]["auditable_metadata"].is_null());
    assert!(evidence["normalized_result"]["rustc_commit"].is_null());
    assert_eq!(evidence["provider"]["id"], "rust-auditable");
    assert_eq!(evidence["parameters"]["path"], path.to_str().unwrap());
    assert_eq!(
        evidence["locations"],
        serde_json::json!([{"kind":"artifact-path","path":path}])
    );
    assert_eq!(
        evidence["limitations"],
        evidence["normalized_result"]["limitations"]
    );
    directory.close().unwrap();
}

#[test]
fn evidence_import_authenticates_a_complete_bundle_and_reports_counts() {
    let directory = tempfile::tempdir().unwrap();
    let artifact_path = directory.path().join("example");
    fs::write(&artifact_path, fixture()).unwrap();

    let inspected = inspect(&artifact_path);
    assert!(inspected.status.success(), "{:?}", inspected);
    let record = json(&inspected);
    let subject = &record["subject"];
    let identity = serde_json::json!({
        "domain": "fixture",
        "question": "Which observation is complete?",
        "scope_digest": null,
    });
    let identity = serde_json::value::to_raw_value(&identity).unwrap();
    let unknown_id = format!("unk_{}", canonical_json::digest_raw(&identity).unwrap());
    let mut unknown = serde_json::json!({
        "unknown_id": unknown_id,
        "revision": 1,
        "previous_revision_digest": null,
        "scope_digest": null,
        "question": "Which observation is complete?",
        "status": "open",
        "severity": "low",
        "domain": "fixture",
        "supporting_evidence_ids": [],
        "contradicting_evidence_ids": [],
        "required_authority": null,
        "required_confidence": "inferred",
        "required_environment": null,
        "recommended_probes": [],
        "relationships": [],
        "resolution": null,
        "mutation_evidence_ids": [record["evidence_id"]],
    });
    let unsigned_unknown = serde_json::value::to_raw_value(&unknown).unwrap();
    let revision_digest = canonical_json::digest_raw(&unsigned_unknown).unwrap();
    unknown["revision_digest"] = Value::String(revision_digest);
    let bundle_path = directory.path().join("bundle.json");
    let bundle = serde_json::json!({
        "artifacts": [{
            "digest": subject["digest"],
            "format": subject["format"],
            "architecture": subject["architecture"],
        }],
        "providers": [record["provider"]],
        "environments": [],
        "scenarios": [],
        "captures": [],
        "unknowns": [unknown],
        "records": [record],
    });
    fs::write(&bundle_path, serde_json::to_vec(&bundle).unwrap()).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_rea-native"))
        .args([
            "evidence-import",
            bundle_path.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .unwrap();

    assert!(output.status.success(), "{:?}", output);
    assert!(output.stderr.is_empty());
    assert_eq!(
        json(&output),
        serde_json::json!({
            "imported": 1,
            "unknowns_added": 1,
            "total": 1,
        })
    );
    directory.close().unwrap();
}

#[test]
fn evidence_export_authenticates_and_atomically_writes_canonical_bundle() {
    let directory = tempfile::tempdir().unwrap();
    let artifact_path = directory.path().join("example");
    fs::write(&artifact_path, fixture()).unwrap();

    let inspected = inspect(&artifact_path);
    assert!(inspected.status.success(), "{:?}", inspected);
    let record = json(&inspected);
    let bundle = bundle_for(&record);
    let source = directory.path().join("source.json");
    let output_path = directory.path().join("export.json");
    fs::write(&source, serde_json::to_vec(&bundle).unwrap()).unwrap();

    let output = export(&source, &output_path, &[]);
    assert!(output.status.success(), "{:?}", output);
    assert!(output.stderr.is_empty());
    let receipt = json(&output);
    let canonical_bytes = fs::read(&output_path).unwrap();
    assert_eq!(receipt["path"], output_path.to_str().unwrap());
    assert_eq!(receipt["bytes"], canonical_bytes.len());
    assert_eq!(receipt["records"], 1);
    assert_eq!(
        serde_json::from_slice::<Value>(&canonical_bytes).unwrap(),
        bundle
    );

    let rejected = export(&source, &output_path, &[]);
    assert_eq!(rejected.status.code(), Some(1));
    assert!(rejected.stderr.is_empty());
    assert_eq!(json(&rejected)["error"], "Analysis failed");
    assert_eq!(json(&rejected)["code"], "invalid_request");
    assert_eq!(fs::read(&output_path).unwrap(), canonical_bytes);

    let replaced = export(&source, &output_path, &["--overwrite"]);
    assert!(replaced.status.success(), "{:?}", replaced);
    assert!(replaced.stderr.is_empty());
    assert_eq!(fs::read(&output_path).unwrap(), canonical_bytes);

    let in_place = export(&source, &source, &["--overwrite"]);
    assert!(in_place.status.success(), "{:?}", in_place);
    assert_eq!(fs::read(&source).unwrap(), canonical_bytes);

    let invalid_source = directory.path().join("invalid.json");
    let invalid_output = directory.path().join("must-not-exist.json");
    fs::write(&invalid_source, b"{}").unwrap();
    let rejected = export(&invalid_source, &invalid_output, &[]);
    assert_eq!(rejected.status.code(), Some(1));
    assert!(rejected.stderr.is_empty());
    assert!(!invalid_output.exists());
    directory.close().unwrap();
}

#[test]
fn compare_reports_canonical_bundle_identity_and_unchanged_records() {
    let directory = tempfile::tempdir().unwrap();
    let artifact_path = directory.path().join("example");
    fs::write(&artifact_path, fixture()).unwrap();
    let inspected = inspect(&artifact_path);
    assert!(inspected.status.success(), "{:?}", inspected);

    let bundle = bundle_for(&json(&inspected));
    let left_path = directory.path().join("left.json");
    let right_path = directory.path().join("right.json");
    fs::write(&left_path, serde_json::to_vec_pretty(&bundle).unwrap()).unwrap();
    fs::write(&right_path, serde_json::to_vec(&bundle).unwrap()).unwrap();

    let output = compare(&left_path, &right_path);

    assert!(output.status.success(), "{:?}", output);
    assert!(output.stderr.is_empty());
    let result = json(&output);
    assert_eq!(result["status"], "unchanged");
    assert_eq!(result["left_bundle_sha256"], result["right_bundle_sha256"]);
    assert_eq!(result["summary"]["records_unchanged"], 1);
    assert_eq!(result["summary"]["records_changed"], 0);
    assert_eq!(result["summary"]["unknowns_unchanged"], 0);
    assert_eq!(result["summary"]["unresolved"], 0);
    assert_eq!(result["changes"], serde_json::json!([]));
    assert_eq!(result["limitations"], serde_json::json!([]));
    directory.close().unwrap();
}

#[test]
fn compare_reports_malformed_bundles_as_non_retryable_integrity_failures() {
    let directory = tempfile::tempdir().unwrap();
    let malformed_path = directory.path().join("malformed.json");
    fs::write(&malformed_path, b"{}").unwrap();

    let output = compare(&malformed_path, &malformed_path);

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let failure = json(&output);
    assert_eq!(failure["error"], "Analysis failed");
    assert_eq!(failure["code"], "evidence_integrity_mismatch");
    assert_eq!(failure["category"], "integrity_mismatch");
    assert!(!failure["retryable"].as_bool().unwrap());
    assert_eq!(failure["details"]["operation"], "compare_bundles");
    let message = "Evidence bundle does not match the bundle schema at artifacts: Invalid input: expected array, received undefined (6 more issues). Supply an unmodified bundle written by export_evidence_bundle or rea evidence-export.";
    assert_eq!(failure["message"], message);
    assert_eq!(failure["remediation"]["action"], message);
    assert_eq!(
        failure["details"]["reason"],
        "Evidence bundle validation failed"
    );
    directory.close().unwrap();
}

#[test]
fn compare_keeps_one_sided_record_membership_unresolved() {
    let directory = tempfile::tempdir().unwrap();
    let left_artifact = directory.path().join("left-artifact");
    let right_artifact = directory.path().join("right-artifact");
    fs::write(&left_artifact, fixture()).unwrap();
    fs::write(&right_artifact, fixture()).unwrap();

    let left_record = json(&inspect(&left_artifact));
    let right_record = json(&inspect(&right_artifact));
    let left_path = directory.path().join("left.json");
    let right_path = directory.path().join("right.json");
    fs::write(
        &left_path,
        serde_json::to_vec(&bundle_for(&left_record)).unwrap(),
    )
    .unwrap();
    fs::write(
        &right_path,
        serde_json::to_vec(&bundle_for(&right_record)).unwrap(),
    )
    .unwrap();

    let output = compare(&left_path, &right_path);

    assert!(output.status.success(), "{:?}", output);
    assert!(output.stderr.is_empty());
    let result = json(&output);
    assert_eq!(result["status"], "unknown");
    assert_eq!(result["summary"]["records_unchanged"], 0);
    assert_eq!(result["summary"]["records_added"], 0);
    assert_eq!(result["summary"]["records_removed"], 0);
    assert_eq!(result["summary"]["unresolved"], 2);
    assert_eq!(result["changes"].as_array().unwrap().len(), 2);
    assert_eq!(
        result["limitations"],
        serde_json::json!([
            "EvidenceBundle has no inventory completeness marker; one-sided membership remains unknown."
        ])
    );
    for change in result["changes"].as_array().unwrap() {
        assert_eq!(change["classification"], "unknown");
        assert_eq!(change["conclusion_kind"], "unresolved_branch");
        assert_eq!(change["limitations"].as_array().unwrap().len(), 1);
    }
    directory.close().unwrap();
}

#[test]
fn compare_distinguishes_advanced_and_diverged_unknown_histories() {
    let directory = tempfile::tempdir().unwrap();
    let artifact_path = directory.path().join("example");
    fs::write(&artifact_path, fixture()).unwrap();
    let inspected = inspect(&artifact_path);
    assert!(inspected.status.success(), "{:?}", inspected);
    let record = json(&inspected);

    let first = unknown_revision(&record["evidence_id"], 1, None, "open");
    let first_digest = first["revision_digest"].as_str().unwrap().to_owned();
    let advanced = unknown_revision(
        &record["evidence_id"],
        2,
        Some(&first_digest),
        "investigating",
    );
    let left_path = directory.path().join("left.json");
    let right_path = directory.path().join("right.json");
    fs::write(
        &left_path,
        serde_json::to_vec(&bundle_with_unknowns(&record, vec![first.clone()])).unwrap(),
    )
    .unwrap();
    fs::write(
        &right_path,
        serde_json::to_vec(&bundle_with_unknowns(
            &record,
            vec![first.clone(), advanced.clone()],
        ))
        .unwrap(),
    )
    .unwrap();

    let advanced_output = compare(&left_path, &right_path);
    assert!(advanced_output.status.success(), "{:?}", advanced_output);
    let advanced_result = json(&advanced_output);
    assert_eq!(advanced_result["status"], "changed");
    assert_eq!(advanced_result["summary"]["unknowns_advanced"], 1);
    assert_eq!(advanced_result["summary"]["unresolved"], 0);
    assert_eq!(
        advanced_result["changes"][0]["classification"],
        "history_advanced"
    );
    assert_eq!(
        advanced_result["changes"][0]["conclusion_kind"],
        "observed_change"
    );

    let diverged = unknown_revision(&record["evidence_id"], 2, Some(&first_digest), "blocked");
    fs::write(
        &left_path,
        serde_json::to_vec(&bundle_with_unknowns(
            &record,
            vec![first.clone(), advanced.clone()],
        ))
        .unwrap(),
    )
    .unwrap();
    fs::write(
        &right_path,
        serde_json::to_vec(&bundle_with_unknowns(&record, vec![first, diverged])).unwrap(),
    )
    .unwrap();

    let diverged_output = compare(&left_path, &right_path);
    assert!(diverged_output.status.success(), "{:?}", diverged_output);
    let diverged_result = json(&diverged_output);
    assert_eq!(diverged_result["status"], "unknown");
    assert_eq!(diverged_result["summary"]["unknowns_diverged"], 1);
    assert_eq!(diverged_result["summary"]["unresolved"], 1);
    assert_eq!(
        diverged_result["changes"][0]["classification"],
        "history_diverged"
    );
    assert_eq!(
        diverged_result["changes"][0]["conclusion_kind"],
        "contradiction"
    );
    directory.close().unwrap();
}

#[test]
fn cli_reports_expected_failures_without_following_a_final_symlink() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("text");
    fs::write(&path, b"plain text").unwrap();
    let link = directory.path().join("link");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    let missing = directory.path().join("missing");
    for (path, code, reason) in [
        (&path, "unsupported_target", None),
        (&link, "invalid_request", Some("invalid_format")),
        (&missing, "invalid_request", Some("invalid_value")),
    ] {
        let output = inspect(path);
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stderr.is_empty());
        let failure = json(&output);
        assert_eq!(failure["code"], code);
        assert_eq!(failure["details"]["operation"], "inspect_rust_binary");
        if let Some(reason) = reason {
            assert_eq!(failure["details"]["issues"][0]["reason"], reason);
        }
    }
    directory.close().unwrap();
}

#[test]
fn parent_components_after_symlinks_are_resolved_by_the_filesystem_not_lexically() {
    // getcwd reports the physical base on macOS (/var may be /private/var).
    // Admit that base for this fixture; never normalize the supplied link/.. .
    let directory = tempfile::tempdir_in(fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap();
    let work = directory.path().join("work");
    let other = directory.path().join("other");
    fs::create_dir(&work).unwrap();
    fs::create_dir(&other).unwrap();
    fs::create_dir(other.join("nested")).unwrap();
    std::os::unix::fs::symlink(other.join("nested"), work.join("link")).unwrap();
    fs::write(work.join("example"), b"wrong target").unwrap();
    fs::write(other.join("example"), fixture()).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_rea-native"))
        .current_dir(&work)
        .args([
            "inspect-rust-binary",
            "./link/../example",
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let evidence = json(&output);
    assert_eq!(
        evidence["subject"]["local_path"],
        format!("{}/link/../example", work.display())
    );
    assert_eq!(evidence["normalized_result"]["artifact"]["bytes"], 64);
    directory.close().unwrap();
}

#[test]
fn a_closed_stdout_reader_gets_quiet_sigpipe_status() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("example");
    fs::write(&path, fixture()).unwrap();
    // The reader is gone BEFORE launch, eliminating timing assumptions about
    // whether a tiny result fits in an OS pipe buffer before the parent closes.
    for arguments in [
        vec!["inspect-rust-binary", "--format"],
        vec![
            "inspect-rust-binary",
            path.to_str().unwrap(),
            "--format",
            "json",
        ],
        vec!["--help"],
        vec!["--version"],
        vec!["evidence-import", "--format"],
    ] {
        let (writer, reader) = UnixStream::pair().unwrap();
        drop(reader);
        let fd: OwnedFd = writer.into();
        let output = Command::new(env!("CARGO_BIN_EXE_rea-native"))
            .args(&arguments)
            .stdout(Stdio::from(fd))
            .stderr(Stdio::piped())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(141), "{arguments:?}");
        assert!(output.stderr.is_empty());
    }
    directory.close().unwrap();
}

#[test]
fn unsupported_commands_and_non_unicode_arguments_do_not_panic_or_fall_back() {
    for args in [
        vec![OsString::from("analyze"), OsString::from("/fixture")],
        vec![OsString::from_vec(vec![0xff])],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_rea-native"))
            .args(args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert_eq!(json(&output)["code"], "invalid_request");
        assert!(output.stderr.is_empty());
    }
}
