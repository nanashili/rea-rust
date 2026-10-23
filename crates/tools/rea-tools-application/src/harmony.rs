//! Execution-free HarmonyOS application inventory projection.
//!
//! Compatibility owners: `src/domain/harmony/harmonyApplication.ts` and
//! `src/application/harmony/HarmonyApplicationService.ts`.
use crate::inventory::ParsedInventorySet;
use crate::projection::{
    self, CandidateGroup, InventoryProjection, ends_with_ci, eq_ci, format_of, last_segment,
    path_of,
};
use crate::rejection::Rejection;
use serde_json::{Value, json};
use std::collections::BTreeSet;

pub const OPERATION: &str = "project_harmony_application_graph";

pub const PROJECTION: InventoryProjection = InventoryProjection {
    operation: OPERATION,
    predicate_type: "rea.harmony-application-graph",
    provider: (
        "rea-harmony-application",
        "REA HarmonyOS application workflows",
    ),
    fixed_subject_format: None,
    project,
};

const ROOT_FORMATS: [&str; 3] = ["hap", "hsp", "app-pack"];

/// `projectHarmonyApplication`.
fn project(parsed: &ParsedInventorySet) -> Result<Value, Rejection> {
    let inventory = &parsed.inventory;
    let root_format = inventory.root_format();
    if !ROOT_FORMATS.contains(&root_format) {
        return Err(Rejection::type_error(format!(
            "HarmonyOS application projection requires HAP, HSP, or App Pack inventory Evidence (got {root_format})"
        )));
    }
    let entries = projection::entries(inventory)?;
    let all = projection::file_components(&entries);
    let unavailable = projection::unavailable_components(&entries);
    let pick = |predicate: &dyn Fn(&Value) -> bool| -> Vec<Value> {
        all.iter()
            .filter(|component| predicate(component))
            .cloned()
            .collect()
    };
    let manifests = pick(&|c| {
        let name = last_segment(path_of(c));
        ["module.json", "config.json", "pack.info"]
            .iter()
            .any(|expected| eq_ci(name, expected))
    });
    let bytecode = pick(&|c| ends_with_ci(path_of(c), ".abc") || ends_with_ci(path_of(c), ".pa"));
    let resources = pick(&|c| resource_path(path_of(c)));
    let native_libraries = pick(&|c| {
        format_of(c) == "elf" || projection::library_layout(path_of(c), "libs", "", ".so")
    });
    let javascript = pick(&|c| {
        let path = path_of(c);
        format_of(c) == "javascript-bundle"
            || [".js", ".mjs", ".cjs"]
                .iter()
                .any(|suffix| ends_with_ci(path, suffix))
    });
    let signing = pick(&|c| {
        projection::direct_child_with_extension(
            path_of(c),
            "META-INF",
            &[".p7b", ".sig", ".cer", ".crt", ".pem", ".provision"],
        )
    });
    let (bridges, bridge_coverage) = projection::cartesian_candidates(
        &[CandidateGroup {
            left: bytecode.iter().collect(),
            right: native_libraries.iter().collect(),
        }],
        |managed_path, target| {
            json!({
                "managed_path": managed_path,
                "native_path": path_of(target),
                "basis": if projection::library_layout(path_of(target), "libs", "lib", ".so") {
                    "napi-library-convention"
                } else {
                    "managed-and-native-content"
                },
            })
        },
    );
    let mut families = BTreeSet::new();
    if !bytecode.is_empty() {
        families.insert("ark");
    }
    if all.iter().any(|c| format_of(c) == "elf") {
        families.insert("native");
    }
    if !javascript.is_empty() {
        families.insert("javascript");
    }
    for component in &all {
        if let Some(convention) = projection::native_runtime_convention(path_of(component)) {
            families.insert(convention);
        }
    }
    let mut limitations = inventory.limitations.clone();
    if !inventory.has_complete_coverage("container-entries") {
        limitations.push("Source inventory coverage is partial; absence is unknown.".into());
    }
    if !unavailable.is_empty() {
        limitations.push("Some inventoried occurrences have no authenticated content identity. Their paths and limitations are retained in unavailable_components; component and runtime absence is unknown.".into());
    }
    limitations.extend([
        "Manifest, module, resource, and signing semantics require a dedicated HarmonyOS provider; this projection reports exact inventory paths and hashes only.".to_owned(),
        "The packaging model is a path-presence heuristic: a Stage model is claimed only from module.json and a FA model only from config.json; both can coexist with unusual layouts.".to_owned(),
        "Runtime families are inferred from inventory formats and paths; filename suffixes do not establish valid Ark bytecode.".to_owned(),
        "The signing component lists META-INF certificate-entry suffixes only; signatures applied by the packaging tool live in the ZIP signing block rather than archive entries, so an empty signing list does not mean the package is unsigned.".to_owned(),
        "Bridge candidates are path-based hypotheses, not decoded N-API declarations or observed runtime calls.".to_owned(),
    ]);
    if root_format == "app-pack" {
        limitations.extend([
            "App Pack child packages are listed by inventory path only; their contents are not recursively inventoried by this projection.".to_owned(),
            "The app-pack root classification is a verified-ZIP-magic plus .app suffix rule; the projection does not require pack.info or child packages before reporting the root format.".to_owned(),
        ]);
    }
    limitations.push("HarmonyOS .har shared libraries are not identified by this projection; the .har suffix also names HTTP Archive JSON, so that classification requires verified ZIP bytes.".into());
    if bridge_coverage["status"] == "partial" {
        limitations.push(format!(
            "Bridge candidate pairs exceeded the projection safety budget; {} hypotheses are omitted. Component arrays still include every component from the supplied inventory pages.",
            bridge_coverage["omitted_candidates"]
        ));
    }
    let packaging_model = if manifests
        .iter()
        .any(|c| eq_ci(last_segment(path_of(c)), "module.json"))
    {
        "stage"
    } else if manifests
        .iter()
        .any(|c| eq_ci(last_segment(path_of(c)), "config.json"))
    {
        "fa"
    } else {
        "unknown"
    };
    let app_pack_children: Vec<Value> = if root_format == "app-pack" {
        pick(&|c| ends_with_ci(path_of(c), ".hap") || ends_with_ci(path_of(c), ".hsp"))
    } else {
        Vec::new()
    };
    let budget_complete = bridge_coverage["status"] == "complete" && unavailable.is_empty();
    let result = json!({
        "root_sha256": inventory.root_sha256(),
        "root_format": root_format,
        "source_evidence_ids": projection::source_ids(parsed),
        "packaging_model": packaging_model,
        "components": {
            "manifests": manifests,
            "bytecode": bytecode,
            "resources": resources,
            "native_libraries": native_libraries,
            "javascript": javascript,
            "signing": signing,
        },
        "unavailable_components": unavailable,
        "app_pack_children": app_pack_children,
        "runtime_families": families.into_iter().collect::<Vec<_>>(),
        "bridge_candidates": bridges,
        "bridge_candidate_coverage": bridge_coverage,
        "coverage": projection::coverage(inventory, budget_complete),
        "limitations": limitations,
    });
    projection::identified(result, "hmp", "HarmonyOS application projection")
}

/// `(?:^|\/)resources\.index$` or `^(?:resources\/|assets\/[^/]+\/resources\/)`
/// (case-insensitive).
fn resource_path(path: &str) -> bool {
    if eq_ci(last_segment(path), "resources.index") {
        return true;
    }
    let segments: Vec<&str> = path.split('/').collect();
    (segments.len() >= 2 && eq_ci(segments[0], "resources"))
        || (segments.len() >= 4
            && eq_ci(segments[0], "assets")
            && !segments[1].is_empty()
            && eq_ci(segments[2], "resources"))
}
