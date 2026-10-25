//! Bounded, read-only desktop application directory inspection.
//!
//! This is the application owner for the live desktop workflow.  Traversal,
//! no-follow admission, and stable reads are delegated to `rea-host`.

use rea_core::{
    cancellation::Cancellation,
    canonical_json,
    failure::{Detail, Failure},
};
use rea_host::fs::stable_directory::{DirectoryEntryKind, DirectoryReader};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::Path};

pub const OPERATION: &str = "inspect_desktop_application";
const MAX_RETAINED_PREFIX: usize = 64 * 1024;

/// Inspect a caller-selected directory without executing or mutating it.
pub fn inspect(
    path: &str,
    max_entries: usize,
    max_probe_bytes: usize,
    cancellation: &Cancellation,
) -> Result<Value, Failure> {
    if !Path::new(path).is_absolute() || max_entries == 0 || max_entries > 100_000 {
        return Err(input_failure(
            "path must be absolute and max_entries must be within bounds",
        ));
    }
    if !(4096..=64 * 1024 * 1024).contains(&max_probe_bytes) {
        return Err(input_failure(
            "max_probe_bytes is outside the supported range",
        ));
    }

    let reader = DirectoryReader::open(Path::new(path))
        .map_err(|error| directory_failure(path, error.to_string()))?;
    let root = reader.root();
    let namespace = canonical_json::digest(&json!({
        "path": root.canonical_path.to_string_lossy(),
        "device": root.identity.device,
        "inode": root.identity.file_id,
    }))
    .map_err(|error| internal_failure(error.to_string()))?;
    let namespace_id = format!("dsr_{namespace}");
    let entries = reader
        .entries(max_entries, cancellation)
        .map_err(|error| directory_failure(path, error.to_string()))?;
    let mut files = Vec::new();
    let omissions: Vec<Value> = Vec::new();
    let mut bytes_read = 0usize;
    let mut files_probed = 0usize;
    let mut entries_examined = 0usize;
    let mut symlinks = 0usize;
    let special = 0usize;
    let mut partial = false;

    for entry in entries {
        ensure_active(cancellation)?;
        entries_examined += 1;
        let kind = match entry.kind {
            DirectoryEntryKind::Regular => "file",
            DirectoryEntryKind::Directory => "directory",
            DirectoryEntryKind::Symlink => {
                symlinks += 1;
                "symlink"
            }
        };
        let identity = json!({
            "device": entry.identity.device.to_string(),
            "inode": entry.identity.file_id.to_string(),
            "size": entry.identity.bytes.to_string(),
            "mode": identity_mode(entry.identity.kind),
            "mtime_ns": entry.identity.modified_ns.to_string(),
            "ctime_ns": entry.identity.changed_ns.to_string(),
        });
        let file_id = format!("dsf_{}", canonical_json::digest(&json!({
            "root_namespace_id": namespace_id, "path": entry.path, "kind": kind, "identity": identity
        })).map_err(|error| internal_failure(error.to_string()))?);
        let mut row = json!({
            "file_id": file_id, "path": entry.path, "local_path": Path::new(path).join(&entry.path).to_string_lossy(),
            "kind": kind, "bytes": entry.identity.bytes, "identity": identity,
            "read_status": "not-selected", "ranges": [], "facts": [], "issues": []
        });
        add_path_facts(&mut row, &entry.path);
        if entry.kind == DirectoryEntryKind::Regular
            && probe_selected(&entry.path, &entry.identity)
            && bytes_read < max_probe_bytes
        {
            let remaining = max_probe_bytes - bytes_read;
            let limit = remaining.min(MAX_RETAINED_PREFIX);
            match reader.read_entry_prefix(&entry, limit, cancellation) {
                Ok(data) => {
                    bytes_read = bytes_read.saturating_add(data.len());
                    files_probed += 1;
                    row["read_status"] = Value::String("examined".into());
                    row["ranges"] =
                        json!([{ "offset": 0, "bytes": data.len(), "sha256": hex_digest(&data) }]);
                    let mut observed_facts = row["facts"].as_array().cloned().unwrap_or_default();
                    observed_facts.extend(
                        facts_for(&entry.path, &data)
                            .as_array()
                            .cloned()
                            .unwrap_or_default(),
                    );
                    row["facts"] = Value::Array(observed_facts);
                }
                Err(error) => {
                    partial = true;
                    row["read_status"] = Value::String("unavailable".into());
                    row["issues"] = json!([error.to_string()]);
                }
            }
        }
        files.push(row);
    }
    files.sort_by(|left, right| left["path"].as_str().cmp(&right["path"].as_str()));
    let projection = project_application(&files);
    let snapshot = canonical_json::digest(&json!({"root_namespace_id": namespace_id, "files": files.iter().map(|file| json!({"file_id": file["file_id"], "bytes": file["bytes"], "ranges": file["ranges"]})).collect::<Vec<_>>(), "omissions": omissions}))
        .map_err(|error| internal_failure(error.to_string()))?;
    let report = json!({
        "root": {"path": path, "canonical_path": root.canonical_path, "namespace_id": namespace_id,
            "identity": {"device": root.identity.device.to_string(), "inode": root.identity.file_id.to_string()},
            "snapshot_sha256": snapshot, "identity_scope": "examined-metadata-and-read-ranges"},
        "files": files, "omissions": omissions, "candidates": projection["candidates"], "components": projection["components"], "next_probes": projection["next_probes"],
        "coverage": {"status": if partial {"partial"} else {"complete-within-scan"}, "entries_examined": entries_examined,
            "files_probed": files_probed, "bytes_read": bytes_read, "symlinks_not_followed": symlinks,
            "special_entries_omitted": special, "limits": {"max_entries": max_entries, "max_probe_bytes": max_probe_bytes}},
        "limitations": ["Runtime candidates and component markers do not establish loaded code, execution, or build correspondence.",
            "The directory SHA-256 commits only to retained paths, omission kinds, available filesystem metadata and read-range digests, not to every file's contents. Unread bytes are unknown.",
            "Special-entry payloads are not read. Child symlinks are not followed. This is a sequence of stable entry observations, not an atomic snapshot."]
    });
    Ok(report)
}

fn facts_for(path: &str, data: &[u8]) -> Value {
    let mut facts = Vec::new();
    let lower = path.to_ascii_lowercase();
    if data.starts_with(b"MZ") {
        if data.len() >= 0x40 {
            let pe_offset =
                u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
            if pe_offset + 6 <= data.len() && &data[pe_offset..pe_offset + 4] == b"PE\0\0" {
                facts.push(json!({"kind":"native-image-header","offset":pe_offset,"value":{"format":"pe","machine":u16::from_le_bytes([data[pe_offset+4],data[pe_offset+5]])}}));
                if pe_offset + 24 <= data.len() {
                    let optional_size =
                        u16::from_le_bytes([data[pe_offset + 20], data[pe_offset + 21]]) as usize;
                    let optional_start = pe_offset + 24;
                    if optional_size >= 96 && optional_start + optional_size <= data.len() {
                        let directory =
                            if u16::from_le_bytes([data[optional_start], data[optional_start + 1]])
                                == 0x20b
                            {
                                112
                            } else {
                                96
                            };
                        let cli = optional_start + directory + 14 * 8;
                        if cli + 8 <= optional_start + optional_size {
                            let rva = u32::from_le_bytes([
                                data[cli],
                                data[cli + 1],
                                data[cli + 2],
                                data[cli + 3],
                            ]);
                            let bytes = u32::from_le_bytes([
                                data[cli + 4],
                                data[cli + 5],
                                data[cli + 6],
                                data[cli + 7],
                            ]);
                            if rva != 0 && bytes != 0 {
                                facts.push(json!({"kind":"pe-cli-directory","offset":cli,"value":{"rva":rva,"bytes":bytes}}));
                            }
                        }
                    }
                }
            }
        }
    }
    if data.starts_with(b"\x7fELF") {
        facts.push(json!({
            "kind": "native-image-header",
            "offset": 0,
            "value": {"format": "elf", "signature": "0x7f454c46"}
        }));
    }
    if data.len() >= 4
        && matches!(
            &data[..4],
            [0xfe, 0xed, 0xfa, 0xce]
                | [0xce, 0xfa, 0xed, 0xfe]
                | [0xfe, 0xed, 0xfa, 0xcf]
                | [0xcf, 0xfa, 0xed, 0xfe]
        )
    {
        facts.push(json!({
            "kind": "native-image-header",
            "offset": 0,
            "value": {"format": "mach-o", "signature": "mach-o"}
        }));
    }
    if data.len() >= 8 && u32::from_le_bytes([data[0], data[1], data[2], data[3]]) == 0xfab11baf {
        facts.push(json!({
            "kind": "il2cpp-metadata-header",
            "offset": 0,
            "value": {
                "magic": "0xfab11baf",
                "raw_version": u32::from_le_bytes([data[4], data[5], data[6], data[7]])
            }
        }));
    }
    if data.starts_with(b"GDPC") {
        facts.push(json!({
            "kind": "godot-pck-header",
            "offset": 0,
            "value": {
                "pack_version": read_u32(data, 4),
                "engine_version": [read_u32(data, 8), read_u32(data, 12), read_u32(data, 16)],
                "placement": "standalone"
            }
        }));
    }
    if data.starts_with(b"FORM") && data.get(8..12) == Some(b"GEN8") {
        facts.push(json!({
            "kind": "gamemaker-form-header",
            "offset": 0,
            "value": {"container": "FORM", "first_chunk": "GEN8"}
        }));
    }
    if lower.ends_with(".asar") {
        facts.push(json!({
            "kind": "electron-asar-convention",
            "offset": null,
            "value": path
        }));
    }
    if lower.contains("globalgamemanagers") || lower.contains("gameassembly") {
        facts.push(json!({
            "kind": "il2cpp-library-convention",
            "offset": null,
            "value": path
        }));
    }

    Value::Array(facts)
}

fn read_u32(data: &[u8], offset: usize) -> u32 {
    data.get(offset..offset + 4)
        .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
        .unwrap_or(0)
}

fn add_path_facts(row: &mut Value, path: &str) {
    let lower = path.to_ascii_lowercase();
    let segments: Vec<&str> = lower.split('/').collect();
    let name = segments.last().copied().unwrap_or_default();
    let resources_archive = segments.iter().rev().nth(1).copied() == Some("resources")
        && matches!(name, "app.asar" | "default_app.asar");
    let unreal = (name.ends_with(".pak") || name.ends_with(".utoc"))
        && segments.windows(2).any(|pair| pair == ["content", "paks"]);
    let il2cpp = matches!(
        name,
        "gameassembly.dll" | "gameassembly.so" | "gameassembly.dylib" | "libil2cpp.so"
    );
    let facts = row["facts"]
        .as_array_mut()
        .expect("new file row facts array");
    if resources_archive {
        facts.push(json!({"kind":"electron-asar-convention","offset":null,"value":path}));
    }
    if unreal {
        facts.push(json!({"kind":"unreal-container-convention","offset":null,"value":path}));
    }
    if il2cpp {
        facts.push(json!({"kind":"il2cpp-library-convention","offset":null,"value":path}));
    }
}

fn probe_selected(path: &str, identity: &rea_host::fs::stable_file::Fingerprint) -> bool {
    if identity.kind != rea_host::fs::stable_file::Kind::Regular {
        return false;
    }
    let lower = path.to_ascii_lowercase();
    lower.ends_with(".exe")
        || lower.ends_with(".dll")
        || lower.ends_with(".so")
        || lower.ends_with(".dylib")
        || lower.ends_with(".pck")
        || lower.ends_with(".utoc")
        || lower.ends_with("global-metadata.dat")
        || lower.ends_with("data.win")
}

fn project_application(files: &[Value]) -> Value {
    let mut candidates = Vec::new();
    let mut probes = Vec::new();
    let mut components = Vec::new();
    let fact_files = |kind: &str| {
        files
            .iter()
            .filter(|file| {
                file["facts"]
                    .as_array()
                    .map(|facts| facts.iter().any(|fact| fact["kind"] == kind))
                    .unwrap_or(false)
            })
            .collect::<Vec<_>>()
    };
    let candidate = |family: &str, basis: &[&Value], rationale: &str, confidence: &str| -> Value {
        let ids = basis
            .iter()
            .filter_map(|file| file["file_id"].as_str())
            .collect::<Vec<_>>();
        let semantic = json!({"family":family,"basis_file_ids":ids,"rationale":rationale,"confidence":confidence});
        with_identifier(semantic, "candidate_id", "dsc_")
    };
    let managed = fact_files("pe-cli-directory");
    if !managed.is_empty() {
        candidates.push(candidate("dotnet", &managed, "PE optional headers declare nonempty CLI directories; CLR execution and metadata validity remain unverified.", "derived"));
    }
    let metadata = fact_files("il2cpp-metadata-header");
    let il2cpp = fact_files("il2cpp-library-convention");
    if !metadata.is_empty() && !il2cpp.is_empty() {
        let basis = [metadata.clone(), il2cpp.clone()].concat();
        candidates.push(candidate(
            "unity-il2cpp",
            &basis,
            "IL2CPP metadata and conventionally named native libraries coexist; build correspondence is unverified.",
            "inferred",
        ));
    }
    for (kind, family, rationale) in [
        (
            "godot-pck-header",
            "godot",
            "A Godot pack header was observed; pack contents and encryption are unexamined.",
        ),
        (
            "gamemaker-form-header",
            "gamemaker",
            "A FORM container begins with a GEN8 chunk; resources remain unexamined.",
        ),
        (
            "electron-asar-convention",
            "electron",
            "An app.asar in resources suggests Electron; archive validity is unverified.",
        ),
        (
            "unreal-container-convention",
            "unreal",
            "Unreal package conventions or an IoStore header were observed.",
        ),
    ] {
        let basis = fact_files(kind);
        if !basis.is_empty() {
            candidates.push(candidate(family, &basis, rationale, "inferred"));
        }
    }
    for file in managed.iter().chain(il2cpp.iter()) {
        let operation = if il2cpp
            .iter()
            .any(|other| other["file_id"] == file["file_id"])
        {
            "open_binary"
        } else {
            "inspect_managed_artifact"
        };
        let semantic = json!({"operation":operation,"path":file["local_path"],"file_id":file["file_id"],"rationale":"Inspect this bounded desktop artifact.","confidence":"inferred"});
        probes.push(with_identifier(semantic, "probe_id", "dsp_"));
    }
    for marker in [
        ("bepinex", "BepInEx", "mod-loader"),
        ("melonloader", "MelonLoader", "mod-loader"),
        ("easyanticheat", "Easy Anti-Cheat", "protection"),
        ("battleye", "BattlEye", "protection"),
    ] {
        let basis = files
            .iter()
            .filter(|file| {
                file["path"]
                    .as_str()
                    .unwrap_or_default()
                    .to_ascii_lowercase()
                    .contains(marker.0)
            })
            .collect::<Vec<_>>();
        if !basis.is_empty() {
            let semantic = json!({"name":marker.1,"category":marker.2,"basis_file_ids":basis.iter().filter_map(|file| file["file_id"].as_str()).collect::<Vec<_>>(),"confidence":"inferred","runtime_presence":"unknown"});
            components.push(with_identifier(semantic, "component_id", "dsm_"));
        }
    }
    json!({"candidates":candidates,"components":components,"next_probes":probes})
}

fn digest_value(value: &Value) -> String {
    canonical_json::digest(value).unwrap_or_else(|_| hex_digest(value.to_string().as_bytes()))
}

fn with_identifier(mut semantic: Value, field: &str, prefix: &str) -> Value {
    let identifier = format!("{prefix}{}", digest_value(&semantic));
    semantic
        .as_object_mut()
        .expect("semantic projection object")
        .insert(field.into(), Value::String(identifier));
    semantic
}

fn identity_mode(kind: rea_host::fs::stable_file::Kind) -> String {
    match kind {
        rea_host::fs::stable_file::Kind::Regular => "regular".into(),
        rea_host::fs::stable_file::Kind::Directory => "directory".into(),
        rea_host::fs::stable_file::Kind::Symlink => "symlink".into(),
        rea_host::fs::stable_file::Kind::Other => "other".into(),
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn ensure_active(cancellation: &Cancellation) -> Result<(), Failure> {
    cancellation.reason().map_or(Ok(()), |reason| {
        Err(Failure::new_with_details(
            "cancelled",
            "cancellation",
            "Desktop inspection was cancelled.".into(),
            false,
            "Retry the selected directory operation.".into(),
            BTreeMap::from([(String::from("reason"), Detail::Text(reason.to_owned()))]),
        ))
    })
}

fn input_failure(message: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "input_validation",
        message.into(),
        false,
        "Correct the selected desktop directory and limits.".into(),
        BTreeMap::new(),
    )
}

fn internal_failure(message: String) -> Failure {
    Failure::new(
        "internal_error",
        "internal",
        message,
        false,
        "Retry the desktop inspection.".into(),
        BTreeMap::new(),
    )
}

fn directory_failure(path: &str, message: String) -> Failure {
    Failure::new_with_details(
        "unavailable",
        "io",
        "Desktop directory inspection could not read the selected path.".into(),
        true,
        "Repair access to the selected directory, then retry.".into(),
        BTreeMap::from([
            (String::from("path"), Detail::Text(path.into())),
            (String::from("reason"), Detail::Text(message)),
        ]),
    )
}
