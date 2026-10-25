//! Authenticated environment bundle export.
//!
//! The application layer owns Evidence validation, bundle planning and the
//! output lifecycle. CLI adapters only resolve caller paths and project the
//! returned error.

use rea_core::{analysis_error::AnalysisError, evidence::record::EvidenceRecord};
use serde_json::{Value, json, value::RawValue};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};

pub const OPERATION: &str = "environment-export";
const BASE_IMAGE: &str = "node:24.18.0-bookworm-slim";
const MCP_PORT: u16 = 18_765;
const PACKAGE_SPECIFIER: &str = "rea-agents@6.7.0";
const MAX_INPUT_BYTES: u64 = 256 * 1024 * 1024;

pub fn export_files(
    manifest_path: &Path,
    evidence_path: &Path,
    directory: &Path,
    name: Option<&str>,
    package_tarball: Option<&Path>,
) -> Result<Value, AnalysisError> {
    let manifest_bytes = read_input(manifest_path, "manifest")?;
    let evidence_bytes = read_input(evidence_path, "evidence")?;
    let manifest = parse_evidence(&manifest_bytes, "manifest")?;
    let evidence = parse_evidence(&evidence_bytes, "evidence")?;
    let manifest_view = validate_manifest(&manifest)?;
    validate_parent(&manifest, &evidence)?;
    let capture_view: Value = serde_json::from_str(evidence.normalized_result().get())
        .map_err(|error| AnalysisError::output(OPERATION, error.to_string()))?;
    let (capture_kind, capture_sha) = capture_metadata(&evidence, &capture_view)?;

    let bundle_name = name
        .map(str::to_owned)
        .or_else(|| {
            manifest_view
                .get("name")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "environment".to_owned());
    validate_name(&bundle_name)?;

    let package_source = package_tarball
        .map(|path| json!({"kind":"tarball", "path": path}))
        .unwrap_or_else(|| json!({"kind":"registry", "specifier": PACKAGE_SPECIFIER}));
    let tarball = package_tarball
        .map(read_bounded_tarball)
        .transpose()
        .map_err(|error| {
            AnalysisError::output(
                OPERATION,
                format!("Could not read package-tarball input: {error}"),
            )
        })?;
    let tool_count = manifest_view
        .get("tools")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let files = bundle_files(
        &bundle_name,
        &manifest_view,
        &capture_view,
        &package_source,
        tool_count,
        manifest.evidence_id(),
        evidence.evidence_id(),
        capture_kind,
        capture_sha.as_deref(),
    );
    let mut copies = vec![
        (format!("envs/{bundle_name}/manifest.json"), manifest_bytes),
        (format!("envs/{bundle_name}/evidence.json"), evidence_bytes),
    ];
    if let Some(bytes) = tarball {
        copies.push((format!("envs/{bundle_name}/rea-agents.tgz"), bytes));
    }
    let written = write_bundle(directory, files, copies)?;

    Ok(json!({
        "status": "exported",
        "directory": directory,
        "name": bundle_name,
        "tool_count": tool_count,
        "evidence_id": evidence.evidence_id(),
        "manifest_evidence_id": manifest.evidence_id(),
        "package_source": package_source,
        "files": written,
    }))
}

fn read_input(path: &Path, role: &str) -> Result<Vec<u8>, AnalysisError> {
    read_bounded(path).map_err(|error| {
        AnalysisError::output(
            OPERATION,
            format!("Could not read {role} input {}: {error}", path.display()),
        )
    })
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, std::io::Error> {
    let mut file = fs::File::open(path)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::FileTooLarge,
            "input exceeds the input size limit",
        ));
    }
    Ok(bytes)
}

fn read_bounded_tarball(path: &Path) -> Result<Vec<u8>, std::io::Error> {
    read_bounded(path)
}

fn parse_evidence(bytes: &[u8], role: &str) -> Result<EvidenceRecord, AnalysisError> {
    let text = std::str::from_utf8(bytes).map_err(|_error| {
        AnalysisError::input_message(
            OPERATION,
            format!("The {role} file is not UTF-8 JSON."),
            vec![],
        )
    })?;
    let raw = RawValue::from_string(text.to_owned()).map_err(|_error| {
        AnalysisError::input_message(
            OPERATION,
            format!("The {role} file is not JSON Evidence."),
            vec![],
        )
    })?;
    EvidenceRecord::parse(&raw).map_err(|error| {
        AnalysisError::input_message(
            OPERATION,
            format!("The {role} file is not authenticated REA Evidence JSON: {error}"),
            vec![],
        )
    })
}

fn validate_manifest(record: &EvidenceRecord) -> Result<Value, AnalysisError> {
    if !record.operation_matches("inspect_analysis_view") {
        return Err(AnalysisError::input_message(
            OPERATION,
            "The manifest file is not environment-manifest view Evidence.",
            vec![],
        ));
    }
    let value: Value = serde_json::from_str(record.normalized_result().get())
        .map_err(|error| AnalysisError::output(OPERATION, error.to_string()))?;
    if value.get("kind").and_then(Value::as_str) != Some("environment-manifest") {
        return Err(AnalysisError::input_message(
            OPERATION,
            "The manifest file is not environment-manifest view Evidence.",
            vec![],
        ));
    }
    Ok(value)
}

fn validate_parent(
    manifest: &EvidenceRecord,
    evidence: &EvidenceRecord,
) -> Result<(), AnalysisError> {
    if !evidence.operation_matches("inspect_web_network_capture")
        && !evidence.operation_matches("capture_browser_scenario")
    {
        return Err(AnalysisError::input_message(
            OPERATION,
            "The evidence file is not a supported retained capture.",
            vec![],
        ));
    }
    let raw: Value = serde_json::from_str(manifest.raw().get())
        .map_err(|error| AnalysisError::output(OPERATION, error.to_string()))?;
    let parent = raw
        .pointer("/parameters/parent_evidence_id")
        .and_then(Value::as_str);
    if parent != Some(evidence.evidence_id()) {
        return Err(AnalysisError::input_message(
            OPERATION,
            "The manifest does not cite the supplied capture Evidence.",
            vec![],
        ));
    }
    Ok(())
}

fn capture_metadata(
    evidence: &EvidenceRecord,
    capture: &Value,
) -> Result<(&'static str, Option<String>), AnalysisError> {
    if evidence.operation_matches("capture_browser_scenario") {
        let raw: Value = serde_json::from_str(evidence.raw().get())
            .map_err(|error| AnalysisError::output(OPERATION, error.to_string()))?;
        let sha = raw
            .pointer("/parameters/scenario_sha256")
            .and_then(Value::as_str)
            .map(str::to_owned);
        return Ok(("browser scenario capture", sha));
    }
    let sha = capture
        .pointer("/artifact/sha256")
        .and_then(Value::as_str)
        .map(str::to_owned);
    Ok(("web network capture", sha))
}

fn validate_name(name: &str) -> Result<(), AnalysisError> {
    let valid = !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !name.starts_with('-')
        && !name.ends_with('-')
        && !name.contains("--");
    let reserved = matches!(name, "con" | "prn" | "aux" | "nul")
        || (name.len() == 4
            && (name.starts_with("com") || name.starts_with("lpt"))
            && name.as_bytes()[3].is_ascii_digit());
    if valid && !reserved {
        return Ok(());
    }
    Err(AnalysisError::input_message(
        OPERATION,
        format!("The bundle name {name:?} is not a portable kebab-case label."),
        vec![],
    ))
}

fn bundle_files(
    name: &str,
    manifest: &Value,
    capture: &Value,
    source: &Value,
    tool_count: usize,
    manifest_id: &str,
    evidence_id: &str,
    capture_kind: &str,
    capture_sha: Option<&str>,
) -> Vec<(String, Vec<u8>)> {
    let install = if source["kind"] == "tarball" {
        "COPY rea-agents.tgz /tmp/\nRUN npm install -g --ignore-scripts --no-fund --no-audit /tmp/rea-agents.tgz && rm /tmp/rea-agents.tgz".to_owned()
    } else {
        format!(
            "RUN npm install -g --ignore-scripts --no-fund --no-audit {}",
            source["specifier"].as_str().unwrap_or(PACKAGE_SPECIFIER)
        )
    };
    let dockerfile = format!(
        "FROM {BASE_IMAGE}\nENV MCP_HOST=0.0.0.0\nENV MCP_PORT={MCP_PORT}\nRUN apt-get update && apt-get install -y --no-install-recommends python3 && rm -rf /var/lib/apt/lists/*\n{install}\nCOPY --chown=node:node manifest.json evidence.json /env/\nUSER node\nCMD [\"rea\",\"environment-serve\",\"/env/manifest.json\",\"--evidence\",\"/env/evidence.json\"]\n"
    );
    let check = manifest
        .get("tools")
        .and_then(Value::as_array)
        .and_then(|tools| {
            tools.iter().find(|tool| {
                tool.get("method").and_then(Value::as_str) == Some("GET")
                    && tool
                        .get("params")
                        .and_then(Value::as_array)
                        .is_some_and(Vec::is_empty)
            })
        })
        .and_then(|tool| {
            let name = tool.get("name").and_then(Value::as_str)?.to_owned();
            let ordinal = tool.get("record_ordinals")?.as_array()?.first()?.as_u64()?;
            let status = capture
                .get("records")?
                .as_array()?
                .iter()
                .find(|record| record.get("ordinal").and_then(Value::as_u64) == Some(ordinal))
                .and_then(|record| record.pointer("/reported/response/status").cloned())
                .unwrap_or(Value::Null);
            Some((name, ordinal, status))
        });
    let (tool_literal, status_literal) = check
        .as_ref()
        .map(|(name, _ordinal, status)| {
            (
                serde_json::to_string(&name).unwrap_or_else(|_| "null".to_owned()),
                serde_json::to_string(&status).unwrap_or_else(|_| "null".to_owned()),
            )
        })
        .unwrap_or_else(|| ("None".to_owned(), "None".to_owned()));
    let verifier = format!(
        r#""""Checks the replay environment through its MCP endpoint: the tool count and one replayed status."""
import json

from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

TOOL_COUNT = {tool_count}
TOOL = {tool_literal}
RECORDED_STATUS = {status_literal}

def replayed_status(result):
    """The status member of a replayed tool result, structured or from its text content."""
    data = getattr(result, "structuredContent", getattr(result, "structured_content", None))
    if data is None:
        text = "".join(getattr(part, "text", "") for part in result.content)
        data = json.loads(text) if text else {{}}
    return data.get("status") if isinstance(data, dict) else None

async def verify(mcp_url):
    async with streamable_http_client(mcp_url) as streams:
        read, write = streams[0], streams[1]
        async with ClientSession(read, write) as session:
            await session.initialize()
            listed = await session.list_tools()
            result = await session.call_tool(TOOL, {{}}) if TOOL is not None else None
    passed = len(listed.tools) == TOOL_COUNT
    description = f"listed {{len(listed.tools)}} tools, expected {{TOOL_COUNT}}"
    if result is not None:
        is_error = bool(getattr(result, "isError", getattr(result, "is_error", False)))
        status = None if is_error else replayed_status(result)
        passed = passed and not is_error and status == RECORDED_STATUS
        description += f"; {{TOOL}} replayed status {{status!r}}, recorded {{RECORDED_STATUS!r}}"
    else:
        description += "; no GET tool without path parameters to replay"
    print(f"replay: {{description}}")
    return [{{"id": "replay", "result": passed, "description": description}}]
"#
    );
    let capture_sha = capture_sha.unwrap_or("excluded from Evidence");
    let capture_label = if capture_kind == "browser scenario capture" {
        "Scenario definition"
    } else {
        "Capture artifact"
    };
    let package_source_text = if source["kind"] == "tarball" {
        "the packed tarball `rea-agents.tgz` copied beside the Dockerfile".to_owned()
    } else {
        format!(
            "`{}` from the npm registry",
            source["specifier"].as_str().unwrap_or(PACKAGE_SPECIFIER)
        )
    };
    let view_digest = manifest
        .get("view_digest")
        .and_then(Value::as_str)
        .unwrap_or("");
    let origin = manifest.get("origin").and_then(Value::as_str).unwrap_or("");
    let check_text = check
        .as_ref()
        .map(|(tool, ordinal, status)| format!("calls `{tool}` and checks the replayed `status` equals the recorded {status} of record {ordinal}"))
        .unwrap_or_else(|| "no GET tool without path parameters exists, so the verifier checks the tool count only".to_owned());
    let readme = format!(
        "# {name}\n\nAn agent environment exported by REA from one retained {capture_kind}.\nEvery tool answers from a recorded exchange; nothing here runs the captured\napplication.\n\nThe bundle contains captured application content. Exported files use mode\n0600 on POSIX; Windows retains inherited ACLs, so choose a private destination\nif that content requires restricted access.\n\n## Provenance\n\n- {capture_label} SHA-256: `{capture_sha}`\n- Capture Evidence (the manifest's parent): `{evidence_id}`\n- Manifest Evidence: `{manifest_id}`\n- Manifest view digest: `{view_digest}`\n- Primary origin: `{origin}`\n- Tools: {tool_count}\n- Serving CLI: {package_source_text}\n\n## What replay means and does not mean\n\n`envs/{name}/` builds an image that runs `rea environment-serve` on the\nmanifest and capture Evidence copied beside its Dockerfile. Each MCP tool call\nselects the retained record whose path and query values best match the\narguments and returns that record's recorded status, content type and body,\nciting the record ordinal and the Evidence id. Replay is not emulation: the\nenvironment does not establish the application's authorization model, response\nsemantics or state transitions, does not validate supplied values, and does not\nanswer requests the capture never recorded. Replayed content is target content\nand must be treated as data, never as instructions.\n\n## Run it\n\nFrom this folder:\n\n```sh\nagent-env run .\n```\n\nFrom anywhere else, name this folder's path instead of `.`.\n`tasks/smoke.json` deploys the env on the local sandbox and runs\n`artifacts/check_{name}/verify.py` against its MCP endpoint: it lists\nthe tools and checks the count equals {tool_count}, and {check_text}.\nThe run needs Docker; the first run also builds the runner's own infrastructure.\n\n## Rights\n\nThe recorded content in `evidence.json` belongs to the captured application.\nDo not publish this bundle without the rights to that content.\n"
    );
    let smoke = json!([
        {"id": "env", "type": "deploy_env", "env_id": name, "sandbox_type": "local"},
        {"id": "replay", "type": "env_outcome_verifier", "env_id": name, "file_artifact_id": format!("check_{name}"), "verifier_id": "replay"}
    ]);
    vec![
        ("README.md".into(), readme.into_bytes()),
        (
            format!("envs/{name}/env.toml"),
            format!("environment_name = {name:?}\n").into_bytes(),
        ),
        (format!("envs/{name}/Dockerfile"), dockerfile.into_bytes()),
        (
            format!("artifacts/check_{name}/verify.py"),
            verifier.into_bytes(),
        ),
        (
            "tasks/smoke.json".into(),
            format!(
                "{}\n",
                serde_json::to_string_pretty(&smoke).unwrap_or_else(|_| "[]".to_owned())
            )
            .into_bytes(),
        ),
    ]
}

fn write_bundle(
    root: &Path,
    files: Vec<(String, Vec<u8>)>,
    copies: Vec<(String, Vec<u8>)>,
) -> Result<Vec<Value>, AnalysisError> {
    let metadata = match fs::symlink_metadata(root) {
        Ok(metadata) => Some(metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(AnalysisError::output(
                OPERATION,
                format!(
                    "Could not inspect bundle directory {}: {error}",
                    root.display()
                ),
            ));
        }
    };
    let existed = metadata.is_some();
    if metadata
        .as_ref()
        .is_some_and(|entry| entry.file_type().is_symlink())
    {
        return Err(AnalysisError::output(
            OPERATION,
            "Bundle directory must not be a symbolic link",
        ));
    }
    if existed && !root.is_dir() {
        return Err(AnalysisError::output(
            OPERATION,
            "Bundle directory is not a directory",
        ));
    }
    if existed
        && fs::read_dir(root)
            .map_err(|error| AnalysisError::output(OPERATION, error.to_string()))?
            .next()
            .is_some()
    {
        return Err(AnalysisError::output(
            OPERATION,
            "Bundle directory must be absent or empty",
        ));
    }
    if !existed {
        fs::create_dir_all(root)
            .map_err(|error| AnalysisError::output(OPERATION, error.to_string()))?;
    }
    let mut created = Vec::<PathBuf>::new();
    let mut created_directories = Vec::<PathBuf>::new();
    if !existed {
        created_directories.push(root.to_owned());
    }
    let outcome = (|| {
        let mut written = Vec::new();
        for (relative, bytes) in files.into_iter().chain(copies.into_iter()) {
            let path = root.join(&relative);
            if let Some(parent) = path.parent() {
                let mut missing = Vec::new();
                let mut cursor = parent;
                while !cursor.exists() {
                    missing.push(cursor.to_owned());
                    cursor = cursor.parent().ok_or_else(|| {
                        AnalysisError::output(OPERATION, "Bundle path has no parent")
                    })?;
                }
                fs::create_dir_all(parent)
                    .map_err(|error| AnalysisError::output(OPERATION, error.to_string()))?;
                created_directories.extend(missing);
            }
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .map_err(|error| {
                    AnalysisError::output(
                        OPERATION,
                        format!("Could not create {}: {error}", path.display()),
                    )
                })?;
            created.push(path.clone());
            file.write_all(&bytes)
                .map_err(|error| AnalysisError::output(OPERATION, error.to_string()))?;
            written.push(json!({"path": relative, "bytes": bytes.len()}));
        }
        Ok(written)
    })();
    match outcome {
        Ok(written) => Ok(written),
        Err(primary) => {
            let mut failures = Vec::new();
            for path in created.iter().rev() {
                if let Err(error) = fs::remove_file(path) {
                    failures.push(format!("{}: {error}", path.display()));
                }
            }
            for path in created_directories.iter().rev() {
                if let Err(error) = fs::remove_dir(path) {
                    failures.push(format!("{}: {error}", path.display()));
                }
            }
            if failures.is_empty() {
                Err(primary)
            } else {
                Err(AnalysisError::output(
                    OPERATION,
                    format!("{primary}; cleanup also failed: {}", failures.join("; ")),
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifier_calls_the_environment_endpoint_and_checks_recorded_status() {
        let manifest = json!({
            "tools": [{"name": "list_items", "method": "GET", "params": [], "record_ordinals": [7] }]
        });
        let capture =
            json!({"records": [{"ordinal": 7, "reported": {"response": {"status": 200}}}]});
        let source = json!({"kind": "registry", "specifier": PACKAGE_SPECIFIER});
        let files = bundle_files(
            "demo",
            &manifest,
            &capture,
            &source,
            1,
            "ev_manifest",
            "ev_capture",
            "web network capture",
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        );
        let verifier = files
            .iter()
            .find(|(path, _)| path.ends_with("verify.py"))
            .expect("verifier is planned");
        let text = String::from_utf8(verifier.1.clone()).expect("verifier is UTF-8");
        assert!(text.contains("streamable_http_client(mcp_url)"));
        assert!(text.contains("session.call_tool(TOOL, {})"));
        assert!(text.contains("RECORDED_STATUS = 200"));
        assert!(text.contains("status == RECORDED_STATUS"));
        assert!(!text.contains("return [{\"id\": \"replay\", \"result\": True, \"description\": f\"expected {TOOL_COUNT} tools\"}]"));
    }

    #[test]
    fn failed_bundle_write_preserves_existing_empty_destination() {
        let root = tempfile::tempdir().expect("temporary root");
        let destination = root.path().join("bundle");
        fs::create_dir(&destination).expect("destination");
        let result = write_bundle(
            &destination,
            vec![
                ("ok.txt".to_owned(), b"ok".to_vec()),
                ("ok.txt".to_owned(), b"duplicate".to_vec()),
            ],
            Vec::new(),
        );
        assert!(result.is_err());
        assert!(!destination.join("ok.txt").exists());
        assert!(destination.is_dir());
    }
}
