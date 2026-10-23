//! Candidate, component and next-probe projection over admitted desktop facts.
//!
//! Byte-for-byte port of `projectDesktopApplication`
//! (`src/domain/desktopApplicationProjection.ts`). Interprets only the facts
//! the directory reader admitted, never target bytes.

use std::collections::HashSet;

use rea_core::canonical_json;
use serde_json::{Value, json};

use super::convention::{has_easy_anti_cheat_segment, has_path_segment};

/// Decoded IL2CPP metadata versions (`IL2CPP_METADATA_VERSIONS`).
const IL2CPP_METADATA_VERSIONS: [u64; 3] = [29, 31, 39];

/// Insertion-ordered probe set keyed by `probe_id` (TS `Map`).
struct ProbeSet {
    seen: HashSet<String>,
    values: Vec<Value>,
}

impl ProbeSet {
    fn new() -> Self {
        Self {
            seen: HashSet::new(),
            values: Vec::new(),
        }
    }

    fn insert(&mut self, id: String, value: Value) {
        if self.seen.insert(id) {
            self.values.push(value);
        }
    }
}

/// Project `candidates`, `components` and `next_probes` from the file rows.
pub(crate) fn project(files: &[Value]) -> Value {
    let mut candidates: Vec<Value> = Vec::new();
    let mut components: Vec<Value> = Vec::new();
    let mut probes = ProbeSet::new();

    let has = |file: &Value, kind: &str| -> bool {
        file["facts"]
            .as_array()
            .is_some_and(|facts| facts.iter().any(|fact| fact["kind"] == kind))
    };

    let file_id = |file: &Value| file["file_id"].as_str().unwrap_or_default().to_owned();

    let mut push_candidate = |family: &str, basis: &[&Value], rationale: &str, confidence: &str| {
        if basis.is_empty() {
            return;
        }
        let mut ids: Vec<String> = basis.iter().map(|file| file_id(file)).collect();
        ids.sort();
        ids.dedup();
        let semantic = json!({
            "family": family,
            "basis_file_ids": ids,
            "rationale": rationale,
            "confidence": confidence,
        });
        let id = format!("dsc_{}", digest(&semantic));
        candidates.push(prepend_id(&semantic, "candidate_id", &id));
    };

    let push_probe = |probes: &mut ProbeSet, operation: &str, file: &Value, rationale: &str| {
        let semantic = json!({
            "operation": operation,
            "path": file["local_path"],
            "file_id": file["file_id"],
            "rationale": rationale,
            "confidence": "inferred",
        });
        let id = format!("dsp_{}", digest(&semantic));
        probes.insert(id.clone(), prepend_id(&semantic, "probe_id", &id));
    };

    let managed: Vec<&Value> = files
        .iter()
        .filter(|file| has(file, "pe-cli-directory"))
        .collect();
    push_candidate(
        "dotnet",
        &managed,
        "PE optional headers declare nonempty CLI directories; CLR execution and metadata validity remain unverified.",
        "derived",
    );
    for file in &managed {
        push_probe(
            &mut probes,
            "inspect_managed_artifact",
            file,
            "Inspect the declared managed metadata and references.",
        );
    }

    let mono: Vec<&Value> = managed
        .iter()
        .copied()
        .filter(|file| has(file, "unity-assembly-reference"))
        .collect();
    push_candidate(
        "unity-mono",
        &mono,
        "Managed assemblies in a Unity Data/Managed layout reference UnityEngine assemblies.",
        "derived",
    );

    let metadata: Vec<&Value> = files
        .iter()
        .filter(|file| has(file, "il2cpp-metadata-header"))
        .collect();
    for file in &metadata {
        let supported = file["facts"].as_array().is_some_and(|facts| {
            facts.iter().any(|fact| {
                fact["kind"] == "il2cpp-metadata-header"
                    && fact["value"]["raw_version"]
                        .as_u64()
                        .is_some_and(|version| IL2CPP_METADATA_VERSIONS.contains(&version))
            })
        });
        if supported {
            push_probe(
                &mut probes,
                "inspect_il2cpp_metadata",
                file,
                "Inventory this supported-version metadata candidate; complete validity and native binary correspondence remain unverified.",
            );
        }
    }

    let il2cpp: Vec<&Value> = files
        .iter()
        .filter(|file| has(file, "il2cpp-library-convention") && has(file, "native-image-header"))
        .collect();
    if !metadata.is_empty() && !il2cpp.is_empty() {
        let basis: Vec<&Value> = metadata
            .iter()
            .copied()
            .chain(il2cpp.iter().copied())
            .collect();
        push_candidate(
            "unity-il2cpp",
            &basis,
            "IL2CPP metadata headers and conventionally named native libraries coexist; their build correspondence is unverified.",
            "inferred",
        );
        for file in &il2cpp {
            push_probe(
                &mut probes,
                "open_binary",
                file,
                "Inspect this native IL2CPP candidate; metadata-to-address correspondence remains unknown.",
            );
        }
    }

    let godot: Vec<&Value> = files
        .iter()
        .filter(|file| has(file, "godot-pck-header"))
        .collect();
    push_candidate(
        "godot",
        &godot,
        "A standalone or trailer-located Godot pack header was observed; pack contents and encryption are unexamined.",
        "derived",
    );

    let gamemaker: Vec<&Value> = files
        .iter()
        .filter(|file| has(file, "gamemaker-form-header"))
        .collect();
    push_candidate(
        "gamemaker",
        &gamemaker,
        "A FORM container begins with a GEN8 chunk; its game resources remain unexamined.",
        "derived",
    );

    let unreal: Vec<&Value> = files
        .iter()
        .filter(|file| has(file, "unreal-container-convention"))
        .collect();
    push_candidate(
        "unreal",
        &unreal,
        "Unreal Content/Paks paths or an IoStore TOC header suggest an Unreal package layout.",
        "inferred",
    );

    let electron: Vec<&Value> = files
        .iter()
        .filter(|file| has(file, "electron-asar-convention"))
        .collect();
    push_candidate(
        "electron",
        &electron,
        "An app.asar in a resources directory suggests an Electron application; archive validity and execution are unverified.",
        "inferred",
    );
    for file in &electron {
        push_probe(
            &mut probes,
            "open_binary",
            file,
            "Select this ASAR target with open_binary, then call inspect_artifact to inventory it before selecting JavaScript sources.",
        );
        push_probe(
            &mut probes,
            "analyze_javascript_application",
            file,
            "Analyze the candidate application archive with the static JavaScript workflow.",
        );
    }

    let markers: [(&str, &str, &str); 4] = [
        ("bepinex", "BepInEx", "mod-loader"),
        ("melonloader", "MelonLoader", "mod-loader"),
        ("easyanticheat", "Easy Anti-Cheat", "protection"),
        ("battleye", "BattlEye", "protection"),
    ];
    for (segment, name, category) in markers {
        let basis: Vec<&Value> = files
            .iter()
            .filter(|file| {
                let path = file["path"].as_str().unwrap_or_default();
                if segment == "easyanticheat" {
                    has_easy_anti_cheat_segment(path)
                } else {
                    has_path_segment(path, segment)
                }
            })
            .collect();
        if basis.is_empty() {
            continue;
        }
        let semantic = json!({
            "name": name,
            "category": category,
            "basis_file_ids": basis.iter().map(|file| file_id(file)).collect::<Vec<_>>(),
            "confidence": "inferred",
            "runtime_presence": "unknown",
        });
        let id = format!("dsm_{}", digest(&semantic));
        components.push(prepend_id(&semantic, "component_id", &id));
    }

    json!({
        "candidates": candidates,
        "components": components,
        "next_probes": probes.values,
    })
}

/// `dsX_${digestCanonicalValue(semantic, ...)}` — canonical-JSON SHA-256.
fn digest(value: &Value) -> String {
    canonical_json::digest(value).expect("canonical digest of a finite JSON projection")
}

/// Build the identified projection with the id field first, matching the TS
/// object-spread order `{ id, ...semantic }`.
fn prepend_id(semantic: &Value, field: &str, id: &str) -> Value {
    let mut map = serde_json::Map::new();
    map.insert(field.to_owned(), Value::String(id.to_owned()));
    if let Some(object) = semantic.as_object() {
        for (key, value) in object {
            map.insert(key.clone(), value.clone());
        }
    }
    Value::Object(map)
}
