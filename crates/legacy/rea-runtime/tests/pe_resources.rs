#![cfg(unix)]
//! Public CLI/MCP checks for static PE resource Evidence.

#[path = "support/pe_resources.rs"]
mod pe_fixture;

use serde_json::{Value, json};
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    path::Path,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
};

fn inspect_cli(path: &Path, options: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_rea-native"))
        .arg("inspect-pe-resources")
        .arg(path)
        .arg("--json")
        .args(options)
        .output()
        .unwrap()
}

fn parsed(output: &std::process::Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn cli_returns_complete_pe32_and_pe32_plus_resource_evidence() {
    for (plus, format, architecture) in [(false, "pe32", "x86"), (true, "pe32-plus", "x86_64")] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("application.exe");
        let bytes = pe_fixture::fixture(plus);
        fs::write(&path, &bytes).unwrap();

        let output = inspect_cli(&path, &[]);
        assert!(output.status.success(), "{output:?}");
        assert!(output.stderr.is_empty());

        let evidence = parsed(&output);
        let report = &evidence["normalized_result"];
        assert_eq!(evidence["operation"], "inspect_pe_resources");
        assert_eq!(evidence["provider"]["id"], "pe-resource-reader");
        assert_eq!(evidence["parameters"]["path"], path.to_str().unwrap());
        assert_eq!(evidence["parameters"]["max_file_bytes"], 64 * 1024 * 1024);
        assert_eq!(evidence["parameters"]["max_entries"], 16_384);
        assert_eq!(evidence["subject"]["format"], "pe");
        assert_eq!(evidence["subject"]["architecture"], architecture);
        assert_eq!(report["format"], format);
        assert_eq!(report["artifact"]["path"], path.to_str().unwrap());
        assert_eq!(report["artifact"]["bytes"], bytes.len());
        assert_eq!(
            report["artifact"]["sha256"],
            evidence["subject"]["digest"]["sha256"]
        );
        assert_eq!(report["coverage"]["status"], "complete");
        assert_eq!(report["coverage"]["examined_entries"], 12);
        assert_eq!(report["coverage"]["resources"], 5);
        assert_eq!(report["resources"].as_array().unwrap().len(), 5);
        assert_eq!(report["directories"].as_array().unwrap().len(), 8);
        for directory in report["directories"].as_array().unwrap() {
            assert!(directory["location"]["offset"].is_u64());
            assert!(directory["location"]["bytes"].is_u64());
            assert!(directory["named_entries"].is_u64());
            assert!(directory["id_entries"].is_u64());
        }

        let resources = report["resources"].as_array().unwrap();
        assert_eq!(
            resources[0]["payload"]["sha256"],
            "386b0dcff4cf7bf0f7919788ec8ff2d698e532162ae4053d323b8d4fe0bdae94"
        );
        assert_eq!(resources[2]["name"]["kind"], "name");
        assert_eq!(resources[2]["name"]["name"], "7");
        assert_eq!(resources[2]["name"]["utf16le_hex"], "3700");
        assert!(resources[2]["name"]["location"]["offset"].is_u64());
        assert_eq!(resources[3]["name"]["kind"], "id");
        assert_eq!(resources[3]["name"]["id"], 7);
        for resource in resources {
            assert_eq!(resource["entry_locations"].as_array().unwrap().len(), 3);
            assert_eq!(resource["data_entry_location"]["bytes"], 16);
            assert_eq!(resource["code_page"], 65001);
            assert_eq!(resource["reserved"], 0);
            assert!(resource["payload"]["rva"].is_u64());
            assert!(resource["payload"]["location"]["offset"].is_u64());
            assert!(resource["payload"]["location"]["bytes"].is_u64());
        }
        assert_eq!(resources[0]["payload"]["location"]["bytes"], 4);
        assert_eq!(report["icon_groups"][0]["resource_index"], 4);
        assert_eq!(
            report["icon_groups"][0]["images"][0]["candidate_resource_indices"],
            json!([0, 1])
        );
        assert_eq!(
            report["icon_groups"][0]["images"][0]["same_language_resource_index"],
            0
        );
        assert_eq!(
            report["icon_groups"][0]["images"][1]["candidate_resource_indices"],
            json!([])
        );
        assert_eq!(report["icon_groups"][0]["images"][0]["planes"], 1);
        assert_eq!(report["icon_groups"][0]["images"][0]["bit_count"], 32);
        assert_eq!(evidence["limitations"], report["limitations"]);
        let locations = evidence["locations"].as_array().unwrap();
        assert_eq!(locations[0], json!({"kind": "artifact-path", "path": path}));
        assert!(locations.iter().any(|location| {
            location["kind"] == "file-offset-range"
                && location["start"].is_u64()
                && location["end"].is_u64()
                && location["end"].as_u64().unwrap() > location["start"].as_u64().unwrap()
        }));
        let icon_image = &report["icon_groups"][0]["images"][0];
        let icon_start = icon_image["location"]["offset"].as_u64().unwrap();
        let icon_end = icon_start + icon_image["location"]["bytes"].as_u64().unwrap();
        assert!(locations.iter().any(|location| {
            location["kind"] == "file-offset-range"
                && location["start"] == icon_start
                && location["end"] == icon_end
        }));
        let name_location = &resources[2]["name"]["location"];
        let name_start = name_location["offset"].as_u64().unwrap();
        let name_end = name_start + name_location["bytes"].as_u64().unwrap();
        assert!(locations.iter().any(|location| {
            location["kind"] == "file-offset-range"
                && location["start"] == name_start
                && location["end"] == name_end
        }));
    }
}

#[test]
fn cli_returns_structured_error_for_malformed_pe_resource_input() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("malformed.exe");
    fs::write(&path, b"MZ").unwrap();

    let output = inspect_cli(&path, &[]);
    assert!(!output.status.success(), "{output:?}");
    let failure = parsed(&output);
    assert_eq!(failure["code"], "invalid_request");
    assert_eq!(failure["category"], "invalid_input");
    assert_eq!(failure["details"]["operation"], "inspect_pe_resources");
    assert_eq!(failure["details"]["issues"][0]["reason"], "invalid_format");
    assert!(failure["message"].is_string());
}

#[test]
fn cli_projects_string_value_ranges_into_evidence() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("strings.exe");
    let (mut bytes, offsets) = pe_fixture::fixture_with_resource(false, 6, 7, 1033, &[0; 32]);
    let payload_offset = offsets.payload;
    bytes[payload_offset..payload_offset + 32].fill(0);
    bytes[payload_offset..payload_offset + 2].copy_from_slice(&1u16.to_le_bytes());
    bytes[payload_offset + 2..payload_offset + 4].copy_from_slice(&0x00e9u16.to_le_bytes());
    fs::write(&path, &bytes).unwrap();

    let output = inspect_cli(&path, &[]);
    assert!(output.status.success(), "{output:?}");
    let evidence = parsed(&output);
    let strings = evidence["normalized_result"]["strings"].as_array().unwrap();
    assert_eq!(strings[0]["string_id"], 96);
    assert_eq!(strings[0]["value"], "é");
    let value = &strings[0]["value_location"];
    let start = value["offset"].as_u64().unwrap();
    let end = start + value["bytes"].as_u64().unwrap();
    assert!(
        evidence["locations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|location| {
                location["kind"] == "file-offset-range"
                    && location["start"] == start
                    && location["end"] == end
            })
    );
}

#[test]
fn cli_projects_manifest_identity_and_payload_range_into_evidence() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("manifest.exe");
    let (mut bytes, offsets) = pe_fixture::fixture_with_resource(false, 24, 7, 1033, b"<m/>");
    let payload_offset = offsets.payload;
    bytes[payload_offset..payload_offset + 4].copy_from_slice(b"<m/>");
    fs::write(&path, &bytes).unwrap();

    let output = inspect_cli(&path, &[]);
    assert!(output.status.success(), "{output:?}");
    let evidence = parsed(&output);
    let manifest = &evidence["normalized_result"]["manifests"][0];
    assert_eq!(manifest["name"]["id"], 7);
    assert_eq!(manifest["language"]["id"], 1033);
    assert_eq!(manifest["text"], "<m/>");
    let payload = &manifest["location"];
    let start = payload["offset"].as_u64().unwrap();
    let end = start + payload["bytes"].as_u64().unwrap();
    assert!(
        evidence["locations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|location| {
                location["kind"] == "file-offset-range"
                    && location["start"] == start
                    && location["end"] == end
            })
    );
}

#[test]
fn cli_projects_accelerator_entries_and_source_ranges_into_evidence() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("accelerators.exe");
    let (mut bytes, offsets) = pe_fixture::fixture_with_resource(false, 9, 1, 1033, &[0; 12]);
    let payload_offset = offsets.payload;
    bytes[payload_offset..payload_offset + 12]
        .copy_from_slice(&[1, 0, b'A', 0, 7, 0, 0x80, 0, b'B', 0, 9, 0]);
    fs::write(&path, &bytes).unwrap();

    let output = inspect_cli(&path, &[]);
    assert!(output.status.success(), "{output:?}");
    let evidence = parsed(&output);
    let entries = evidence["normalized_result"]["accelerators"][0]["entries"]
        .as_array()
        .unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0]["flags"], 1);
    assert_eq!(entries[0]["key"], 65);
    assert_eq!(entries[0]["command"], 7);
    assert_eq!(entries[1]["is_last"], true);
    let location = &entries[1]["location"];
    let start = location["offset"].as_u64().unwrap();
    let end = start + location["bytes"].as_u64().unwrap();
    assert!(
        evidence["locations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| {
                item["kind"] == "file-offset-range" && item["start"] == start && item["end"] == end
            })
    );
}

#[test]
fn cli_reports_accelerator_tail_without_projecting_partial_entries() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("malformed-accelerators.exe");
    let (mut bytes, offsets) = pe_fixture::fixture_with_resource(false, 9, 1, 1033, &[0; 6]);
    let payload_offset = offsets.payload;
    bytes[payload_offset..payload_offset + 6].copy_from_slice(&[1, 0, b'A', 0, 7, 0]);
    fs::write(&path, &bytes).unwrap();

    let output = inspect_cli(&path, &[]);
    assert!(output.status.success(), "{output:?}");
    let evidence = parsed(&output);
    assert!(
        evidence["normalized_result"]["accelerators"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(
        evidence["limitations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|issue| {
                issue
                    .as_str()
                    .is_some_and(|text| text.contains("RT_ACCELERATOR resource 0 is malformed"))
            })
    );
}

#[test]
fn cli_projects_cursor_group_hotspots_and_source_ranges_into_evidence() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("cursor-group.exe");
    let (mut bytes, offsets) = pe_fixture::fixture_with_resource(false, 12, 1, 1033, &[0; 20]);
    let payload_offset = offsets.payload;
    bytes[payload_offset..payload_offset + 20].fill(0);
    bytes[payload_offset + 2..payload_offset + 4].copy_from_slice(&2u16.to_le_bytes());
    bytes[payload_offset + 4..payload_offset + 6].copy_from_slice(&1u16.to_le_bytes());
    bytes[payload_offset + 6] = 32;
    bytes[payload_offset + 7] = 32;
    bytes[payload_offset + 10..payload_offset + 12].copy_from_slice(&4u16.to_le_bytes());
    bytes[payload_offset + 12..payload_offset + 14].copy_from_slice(&8u16.to_le_bytes());
    bytes[payload_offset + 14..payload_offset + 18].copy_from_slice(&256u32.to_le_bytes());
    bytes[payload_offset + 18..payload_offset + 20].copy_from_slice(&7u16.to_le_bytes());
    fs::write(&path, &bytes).unwrap();

    let output = inspect_cli(&path, &[]);
    assert!(output.status.success(), "{output:?}");
    let evidence = parsed(&output);
    let image = &evidence["normalized_result"]["cursor_groups"][0]["images"][0];
    assert_eq!(image["width"], 32);
    assert_eq!(image["height"], 32);
    assert_eq!(image["hotspot_x"], 4);
    assert_eq!(image["hotspot_y"], 8);
    let start = image["location"]["offset"].as_u64().unwrap();
    let end = start + image["location"]["bytes"].as_u64().unwrap();
    assert!(
        evidence["locations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|location| {
                location["kind"] == "file-offset-range"
                    && location["start"] == start
                    && location["end"] == end
            })
    );
}

#[test]
fn cli_projects_font_directory_entry_ranges_into_evidence() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("font-directory.exe");
    let (mut bytes, offsets) = pe_fixture::fixture_with_resource(false, 7, 1, 1033, &[0; 6]);
    let payload_offset = offsets.payload;
    bytes[payload_offset..payload_offset + 6].copy_from_slice(&[2, 0, 7, 0, 8, 0]);
    fs::write(&path, &bytes).unwrap();

    let output = inspect_cli(&path, &[]);
    assert!(output.status.success(), "{output:?}");
    let evidence = parsed(&output);
    let font = &evidence["normalized_result"]["fonts"][0];
    assert_eq!(font["kind"], "fontdir");
    assert_eq!(font["associated_resource_ids"], json!([7, 8]));
    let entry = &font["entry_locations"][0];
    let start = entry["offset"].as_u64().unwrap();
    let end = start + entry["bytes"].as_u64().unwrap();
    assert!(
        evidence["locations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|location| {
                location["kind"] == "file-offset-range"
                    && location["start"] == start
                    && location["end"] == end
            })
    );
}

#[test]
fn cli_rejects_malformed_group_icon_without_partial_evidence() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("malformed-group-icon.exe");
    let mut bytes = pe_fixture::fixture(false);
    let group = bytes
        .windows(6)
        // RT_GROUP_ICON stores reserved=0, type=1, and image count=2 as
        // little-endian u16 values.
        .position(|window| window == [0, 0, 1, 0, 2, 0])
        .expect("fixture should contain an RT_GROUP_ICON header");
    bytes[group + 4] = 3;
    fs::write(&path, bytes).unwrap();

    let output = inspect_cli(&path, &[]);
    assert!(!output.status.success(), "{output:?}");
    let failure = parsed(&output);
    assert_eq!(failure["code"], "invalid_request");
    assert_eq!(failure["category"], "invalid_input");
    assert_eq!(failure["details"]["operation"], "inspect_pe_resources");
    assert_eq!(failure["details"]["issues"][0]["reason"], "invalid_format");
    assert!(failure.get("normalized_result").is_none());
}

#[test]
fn cli_resource_limits_fail_without_returning_partial_inventory() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("application.exe");
    fs::write(&path, pe_fixture::fixture(false)).unwrap();

    let output = inspect_cli(&path, &["--max-entries", "1"]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");

    let failure = parsed(&output);
    assert_eq!(failure["code"], "resource_constraint");
    assert_eq!(failure["details"]["operation"], "inspect_pe_resources");
    assert_eq!(failure["details"]["resource"], "capacity");
    assert_eq!(
        failure["details"]["reported_limits"]["max_file_bytes"],
        64 * 1024 * 1024
    );
    assert_eq!(failure["details"]["reported_limits"]["max_entries"], 1);
    assert_eq!(failure["retryable"], false);
    assert!(
        failure["remediation"]["action"]
            .as_str()
            .unwrap()
            .contains("Raise max_entries above 1")
    );
    assert!(failure.get("normalized_result").is_none());

    let oversized_read = inspect_cli(&path, &["--max-file-bytes", "64"]);
    assert_eq!(oversized_read.status.code(), Some(1), "{oversized_read:?}");
    let oversized_failure = parsed(&oversized_read);
    assert_eq!(oversized_failure["code"], "resource_constraint");
    assert_eq!(oversized_failure["details"]["resource"], "file-size");
    assert_eq!(
        oversized_failure["details"]["reported_limits"]["max_file_bytes"],
        64
    );
    assert_eq!(
        oversized_failure["details"]["reported_limits"]["max_entries"],
        16_384
    );
    assert_eq!(oversized_failure["retryable"], false);
    assert!(
        oversized_failure["remediation"]["action"]
            .as_str()
            .unwrap()
            .contains("Raise max_file_bytes above 64 bytes")
    );
}

struct McpChild {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}

impl McpChild {
    fn start() -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_rea-native"))
            .arg("mcp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let input = child.stdin.take().unwrap();
        let output = BufReader::new(child.stdout.take().unwrap());
        Self {
            child,
            input,
            output,
        }
    }

    fn request(&mut self, id: u64, method: &str, params: Value) -> Value {
        let request = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });
        writeln!(self.input, "{request}").unwrap();

        let mut line = String::new();
        self.output.read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap()
    }

    fn initialize(&mut self) {
        let response = self.request(
            1,
            "initialize",
            json!({
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "pe-resources-test", "version": "1"},
            }),
        );
        assert!(response["result"].is_object(), "{response}");
    }

    fn call_tool(&mut self, id: u64, name: &str, arguments: Value) -> Value {
        self.request(
            id,
            "tools/call",
            json!({"name": name, "arguments": arguments}),
        )
    }
}

impl Drop for McpChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn mcp_advertises_the_exact_pe_contract_and_retains_inspection_evidence() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("application.exe");
    fs::write(&path, pe_fixture::fixture(false)).unwrap();

    let mut server = McpChild::start();
    server.initialize();

    let listing = server.request(2, "tools/list", json!({}));
    let tools = listing["result"]["tools"].as_array().unwrap();
    let advertised = tools
        .iter()
        .find(|tool| tool["name"] == "inspect_pe_resources")
        .expect("PE resource contract should be advertised");
    let expected: Value =
        serde_json::from_str(include_str!("../contracts/inspect_pe_resources.json")).unwrap();
    assert_eq!(advertised, &expected);

    let inspection = server.call_tool(
        3,
        "inspect_pe_resources",
        json!({"path": path.to_str().unwrap(), "max_entries": 100}),
    );
    assert!(
        inspection["result"].get("isError").is_none(),
        "{inspection}"
    );
    let evidence = &inspection["result"]["structuredContent"];
    assert_eq!(evidence["operation"], "inspect_pe_resources");
    assert_eq!(evidence["parameters"]["max_entries"], 100);
    assert_eq!(evidence["normalized_result"]["coverage"]["resources"], 5);

    let contract = rea_mcp::catalog()
        .tool("inspect_pe_resources")
        .expect("PE resources contract should be available")
        .output_schema()
        .expect("PE resources output schema should be available");
    rea_mcp::schema::validate_named_contract("inspect_pe_resources", contract, evidence)
        .expect("serialized PE report should satisfy its advertised contract");

    let mut invalid_evidence = evidence.clone();
    let icon = invalid_evidence["normalized_result"]["icon_groups"]
        .as_array_mut()
        .and_then(|groups| groups.first_mut())
        .and_then(|group| group["images"].as_array_mut())
        .and_then(|images| images.first_mut())
        .expect("fixture should contain a serialized icon image");
    icon["width"] = json!("32");
    rea_mcp::schema::validate_named_contract("inspect_pe_resources", contract, &invalid_evidence)
        .expect_err("the contract must reject an invalid nested icon field");

    let summary = server.call_tool(4, "get_evidence_bundle", json!({"detail": "summary"}));
    let retained = &summary["result"]["structuredContent"]["result"];
    assert_eq!(retained["total_retained_records"], 1);
    assert_eq!(retained["records"][0]["operation"], "inspect_pe_resources");

    let limited = server.call_tool(
        5,
        "inspect_pe_resources",
        json!({"path": path.to_str().unwrap(), "max_entries": 1}),
    );
    assert_eq!(limited["result"]["isError"], true);
    let failure_text = limited["result"]["content"][0]["text"]
        .as_str()
        .expect("failure should include a text diagnostic");
    let failure_envelope: Value = serde_json::from_str(failure_text).unwrap();
    let failure = &failure_envelope["error"];
    assert_eq!(failure["code"], "resource_constraint");
    assert_eq!(failure["details"]["resource"], "capacity");
    assert_eq!(
        failure["details"]["reported_limits"]["max_file_bytes"],
        64 * 1024 * 1024
    );
    assert_eq!(failure["details"]["reported_limits"]["max_entries"], 1);
    assert_eq!(failure["retryable"], false);
    assert!(
        failure["remediation"]["action"]
            .as_str()
            .unwrap()
            .contains("Raise max_entries above 1")
    );
    assert!(failure.get("normalized_result").is_none());
}

#[test]
fn mcp_advertises_the_wasm_interface_comparison_contract() {
    let mut server = McpChild::start();
    server.initialize();

    let listing = server.request(2, "tools/list", json!({}));
    let tools = listing["result"]["tools"].as_array().unwrap();
    let advertised = tools
        .iter()
        .find(|tool| tool["name"] == "compare_wasm_interfaces")
        .expect("WASM comparison contract should be advertised");
    let expected: Value =
        serde_json::from_str(include_str!("../contracts/compare_wasm_interfaces.json")).unwrap();

    assert_eq!(advertised, &expected);
}

#[test]
fn mcp_advertises_the_plist_contract() {
    let mut server = McpChild::start();
    server.initialize();
    let listing = server.request(2, "tools/list", json!({}));
    let advertised = listing["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == "inspect_plist")
        .expect("plist contract should be advertised");
    let expected: Value =
        serde_json::from_str(include_str!("../contracts/inspect_plist.json")).unwrap();
    assert_eq!(advertised, &expected);
}

#[test]
fn mcp_advertises_the_android_package_contract() {
    let mut server = McpChild::start();
    server.initialize();
    let listing = server.request(2, "tools/list", json!({}));
    let advertised = listing["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == "inspect_android_package")
        .expect("android package contract should be advertised");
    let expected: Value =
        serde_json::from_str(include_str!("../contracts/inspect_android_package.json")).unwrap();
    assert_eq!(advertised, &expected);

    let required = advertised["outputSchema"]["properties"]["result"]["required"]
        .as_array()
        .expect("android output schema should declare required result fields");
    for field in [
        "application_label",
        "resource_variants",
        "signing_blocks",
        "signature_verification",
        "dex",
        "components",
        "features",
        "supports_screens",
        "queries",
        "permission_details",
        "uses_configuration",
    ] {
        assert!(
            required.iter().any(|value| value == field),
            "missing required Android result field: {field}"
        );
    }

    assert_eq!(
        advertised["outputSchema"]["properties"]["result"]["properties"]["signature_verification"]
            ["const"],
        "not_performed"
    );

    let result_properties = &advertised["outputSchema"]["properties"]["result"]["properties"];
    assert_eq!(
        result_properties["features"]["items"]["$ref"],
        "#/outputSchema/properties/result/$defs/usesFeature"
    );
    assert_eq!(
        result_properties["supports_screens"]["$ref"],
        "#/outputSchema/properties/result/$defs/supportsScreens"
    );
    let queries = &result_properties["queries"];
    assert_eq!(queries["anyOf"][0]["type"], "null");
    assert_eq!(
        queries["anyOf"][1]["$ref"],
        "#/outputSchema/properties/result/$defs/queryVisibility"
    );
    assert_eq!(
        "#/outputSchema/properties/result/$defs/queryData",
        advertised["outputSchema"]["properties"]["result"]["$defs"]["queryIntent"]["properties"]["data"]
            ["items"]["$ref"]
    );
    assert_eq!(
        result_properties["permission_details"]["items"]["$ref"],
        "#/outputSchema/properties/result/$defs/permissionDeclaration"
    );
    let uses_configuration = &result_properties["uses_configuration"];
    assert_eq!(uses_configuration["anyOf"][0]["type"], "null");
    assert_eq!(
        uses_configuration["anyOf"][1]["$ref"],
        "#/outputSchema/properties/result/$defs/usesConfiguration"
    );
}

#[test]
fn mcp_advertises_the_bundle_comparison_contract() {
    let mut server = McpChild::start();
    server.initialize();
    let listing = server.request(2, "tools/list", json!({}));
    let advertised = listing["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == "compare_bundles")
        .expect("bundle comparison contract should be advertised");
    let expected: Value =
        serde_json::from_str(include_str!("../contracts/compare_bundles.json")).unwrap();
    assert_eq!(advertised, &expected);
}

#[test]
fn mcp_advertises_the_managed_members_contract() {
    let mut server = McpChild::start();
    server.initialize();
    let listing = server.request(2, "tools/list", json!({}));
    let advertised = listing["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == "inspect_managed_members")
        .expect("managed members contract should be advertised");
    let expected: Value =
        serde_json::from_str(include_str!("../contracts/inspect_managed_members.json")).unwrap();
    assert_eq!(advertised, &expected);
    assert_eq!(
        advertised["inputSchema"]["properties"]["type_names"]["uniqueItems"],
        true
    );
}

#[test]
fn mcp_advertises_the_managed_native_boundaries_contract() {
    let mut server = McpChild::start();
    server.initialize();
    let listing = server.request(2, "tools/list", json!({}));
    let advertised = listing["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == "inspect_managed_native_boundaries")
        .expect("managed native boundaries contract should be advertised");
    let expected: Value = serde_json::from_str(include_str!(
        "../contracts/inspect_managed_native_boundaries.json"
    ))
    .unwrap();
    assert_eq!(advertised, &expected);
    assert_eq!(advertised["inputSchema"]["required"], json!(["path"]));
}

#[test]
fn mcp_advertises_android_class_and_method_contracts() {
    let mut server = McpChild::start();
    server.initialize();
    let listing = server.request(2, "tools/list", json!({}));
    let tools = listing["result"]["tools"].as_array().unwrap();
    for (name, file) in [
        (
            "inspect_android_class",
            "../contracts/inspect_android_class.json",
        ),
        (
            "inspect_android_method",
            "../contracts/inspect_android_method.json",
        ),
    ] {
        let advertised = tools
            .iter()
            .find(|tool| tool["name"] == name)
            .expect("Android class/method contract should be advertised");
        let expected: Value = match file {
            "../contracts/inspect_android_class.json" => {
                serde_json::from_str(include_str!("../contracts/inspect_android_class.json"))
                    .unwrap()
            }
            _ => serde_json::from_str(include_str!("../contracts/inspect_android_method.json"))
                .unwrap(),
        };
        assert_eq!(advertised, &expected);
    }
}

#[test]
fn mcp_advertises_the_android_resource_contract() {
    let mut server = McpChild::start();
    server.initialize();
    let listing = server.request(2, "tools/list", json!({}));
    let advertised = listing["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == "inspect_android_resource")
        .expect("Android resource contract should be advertised");
    let expected: Value =
        serde_json::from_str(include_str!("../contracts/inspect_android_resource.json")).unwrap();
    assert_eq!(advertised, &expected);
}

#[test]
fn mcp_advertises_the_android_manifest_component_contract() {
    let mut server = McpChild::start();
    server.initialize();
    let listing = server.request(2, "tools/list", json!({}));
    let advertised = listing["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == "inspect_android_manifest_component")
        .expect("Android manifest component contract should be advertised");
    let expected: Value = serde_json::from_str(include_str!(
        "../contracts/inspect_android_manifest_component.json"
    ))
    .unwrap();
    assert_eq!(advertised, &expected);
}

#[test]
fn mcp_advertises_the_pe_target_contract() {
    let mut server = McpChild::start();
    server.initialize();
    let listing = server.request(2, "tools/list", json!({}));
    let tool = listing["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == "inspect_pe_target")
        .expect("PE target contract should be advertised");
    let expected: Value =
        serde_json::from_str(include_str!("../contracts/inspect_pe_target.json")).unwrap();
    assert_eq!(tool["inputSchema"], expected["inputSchema"]);
    assert_eq!(tool["outputSchema"], expected["outputSchema"]);
}

#[test]
fn mcp_advertises_the_process_observation_contract() {
    let mut server = McpChild::start();
    server.initialize();
    let listing = server.request(2, "tools/list", json!({}));
    let tool = listing["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == "inspect_process_observation")
        .expect("process observation contract should be advertised");
    let expected: Value = serde_json::from_str(include_str!(
        "../contracts/inspect_process_observation.json"
    ))
    .unwrap();
    assert_eq!(tool["inputSchema"], expected["inputSchema"]);
    assert_eq!(tool["outputSchema"], expected["outputSchema"]);
}

#[test]
fn mcp_advertises_the_evm_interface_contract() {
    let mut server = McpChild::start();
    server.initialize();
    let listing = server.request(2, "tools/list", json!({}));
    let tool = listing["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == "inspect_evm_interface")
        .expect("EVM interface contract should be advertised");
    let expected: Value =
        serde_json::from_str(include_str!("../contracts/inspect_evm_interface.json")).unwrap();
    assert_eq!(tool["inputSchema"], expected["inputSchema"]);
    assert_eq!(tool["outputSchema"], expected["outputSchema"]);
}

#[test]
fn mcp_advertises_the_revert_evidence_contract() {
    let mut server = McpChild::start();
    server.initialize();
    let listing = server.request(2, "tools/list", json!({}));
    let tool = listing["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == "inspect_evm_revert")
        .expect("revert evidence contract should be advertised");
    let expected: Value =
        serde_json::from_str(include_str!("../contracts/inspect_revert_evidence.json")).unwrap();
    assert_eq!(tool["inputSchema"], expected["inputSchema"]);
    assert_eq!(tool["outputSchema"], expected["outputSchema"]);
}

#[test]
fn mcp_advertises_the_macho_contract() {
    let mut server = McpChild::start();
    server.initialize();
    let listing = server.request(2, "tools/list", json!({}));
    let tool = listing["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == "inspect_macho")
        .expect("Mach-O contract should be advertised");
    let expected: Value =
        serde_json::from_str(include_str!("../contracts/inspect_macho.json")).unwrap();
    assert_eq!(tool["inputSchema"], expected["inputSchema"]);
    assert_eq!(tool["outputSchema"], expected["outputSchema"]);
}

#[test]
fn mcp_advertises_the_electron_fuses_contract() {
    let mut server = McpChild::start();
    server.initialize();
    let listing = server.request(2, "tools/list", json!({}));
    let tool = listing["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == "inspect_electron_fuses")
        .expect("Electron fuse contract should be advertised");
    let expected: Value =
        serde_json::from_str(include_str!("../contracts/inspect_electron_fuses.json")).unwrap();
    assert_eq!(tool["inputSchema"], expected["inputSchema"]);
    assert_eq!(tool["outputSchema"], expected["outputSchema"]);
}

#[test]
fn mcp_rejects_an_empty_electron_fuse_path_through_the_named_handler() {
    let mut server = McpChild::start();
    server.initialize();
    let response = server.call_tool(3, "inspect_electron_fuses", json!({"path": ""}));
    assert_eq!(response["result"]["isError"], true);
    assert!(
        response["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("path must be a non-empty string")
    );
}

#[test]
fn mcp_advertises_the_recorded_crash_contract() {
    let mut server = McpChild::start();
    server.initialize();
    let listing = server.request(2, "tools/list", json!({}));
    let tool = listing["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == "inspect_recorded_crash")
        .expect("recorded crash contract should be advertised");
    let expected: Value =
        serde_json::from_str(include_str!("../contracts/inspect_recorded_crash.json")).unwrap();
    assert_eq!(tool["inputSchema"], expected["inputSchema"]);
    assert_eq!(tool["outputSchema"], expected["outputSchema"]);
}

#[test]
fn mcp_advertises_the_binary_layout_contract() {
    let mut server = McpChild::start();
    server.initialize();
    let listing = server.request(2, "tools/list", json!({}));
    let tool = listing["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == "inspect_binary_layout")
        .expect("binary layout contract should be advertised");
    let expected: Value =
        serde_json::from_str(include_str!("../contracts/inspect_binary_layout.json")).unwrap();
    assert_eq!(tool["inputSchema"], expected["inputSchema"]);
    assert_eq!(tool["outputSchema"], expected["outputSchema"]);
}

#[test]
fn mcp_advertises_the_managed_artifact_contract() {
    let mut server = McpChild::start();
    server.initialize();
    let listing = server.request(2, "tools/list", json!({}));
    let tool = listing["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == "inspect_managed_artifact")
        .expect("managed artifact contract should be advertised");
    let expected: Value =
        serde_json::from_str(include_str!("../contracts/inspect_managed_artifact.json")).unwrap();
    assert_eq!(tool["inputSchema"], expected["inputSchema"]);
    assert_eq!(tool["outputSchema"], expected["outputSchema"]);
}
