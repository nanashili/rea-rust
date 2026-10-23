//! Execution-free Android application inventory projection.
//!
//! Compatibility owners: `src/domain/android/androidApplication.ts` and
//! `src/application/android/AndroidApplicationService.ts`.
use crate::inventory::ParsedInventorySet;
use crate::projection::{
    self, CandidateGroup, InventoryProjection, format_of, last_segment, path_of,
};
use crate::rejection::Rejection;
use serde_json::{Value, json};
use std::collections::BTreeSet;

pub const OPERATION: &str = "project_android_application_graph";

pub const PROJECTION: InventoryProjection = InventoryProjection {
    operation: OPERATION,
    predicate_type: "rea.android-application-graph",
    provider: (
        "rea-android-application",
        "REA Android application workflows",
    ),
    fixed_subject_format: Some("apk"),
    project,
};

/// `projectAndroidApplication`.
fn project(parsed: &ParsedInventorySet) -> Result<Value, Rejection> {
    let inventory = &parsed.inventory;
    if inventory.root_format() != "apk" {
        return Err(Rejection::type_error(format!(
            "Android application projection requires APK inventory Evidence; the inventory root format is {}. APK is chosen for a ZIP archive whose name ends in .apk.",
            inventory.root_format()
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
    let manifests = pick(&|c| segment_named(path_of(c), "AndroidManifest.xml"));
    let resources = pick(&|c| segment_named(path_of(c), "resources.arsc"));
    let dex = pick(&|c| projection::segment_has_extension(last_segment(path_of(c)), ".dex"));
    let jvm_classes =
        pick(&|c| projection::segment_has_extension(last_segment(path_of(c)), ".class"));
    let native_libraries = pick(&|c| {
        format_of(c) == "elf" || projection::library_layout(path_of(c), "lib", "", ".so")
    });
    let javascript = pick(&|c| format_of(c) == "javascript-bundle");
    let signing = pick(&|c| {
        projection::direct_child_with_extension(
            path_of(c),
            "META-INF",
            &[".MF", ".RSA", ".DSA", ".EC", ".SF"],
        )
    });
    let managed: Vec<&Value> = dex.iter().chain(jvm_classes.iter()).collect();
    let (bridges, bridge_coverage) = projection::cartesian_candidates(
        &[CandidateGroup {
            left: managed,
            right: native_libraries.iter().collect(),
        }],
        |managed_path, target| {
            json!({
                "managed_path": managed_path,
                "native_path": path_of(target),
                "basis": bridge_basis(path_of(target)),
            })
        },
    );
    let mut families = BTreeSet::new();
    if !dex.is_empty() {
        families.insert("dalvik-art");
    }
    if !jvm_classes.is_empty() {
        families.insert("java-kotlin");
    }
    if all.iter().any(|c| format_of(c) == "elf") {
        families.insert("native");
    }
    if all.iter().any(|c| format_of(c) == "javascript-bundle") {
        families.insert("javascript");
    }
    for component in &all {
        if let Some(convention) = projection::native_runtime_convention(path_of(component)) {
            families.insert(convention);
        }
    }
    let bridge_partial = bridge_coverage["status"] == "partial";
    let mut limitations = inventory.limitations.clone();
    if !inventory.has_complete_coverage("container-entries") {
        limitations.push("Source inventory coverage is partial; absence is unknown.".into());
    }
    limitations.extend([
        "Manifest, resource, signing, and bytecode semantics require a dedicated Android provider; this projection reports exact inventory paths and hashes only.".to_owned(),
        "Runtime families are inferred from inventory formats and paths; filename suffixes do not establish valid DEX or JVM class bytes.".to_owned(),
        "Bridge candidates are path-based hypotheses, not decoded JNI declarations or observed runtime calls.".to_owned(),
        "A bridge basis is inferred from the native path and is repeated for every managed component.".to_owned(),
        "ZIP inventory cannot see the APK Signing Block, so an empty signing array does not mean the APK is unsigned.".to_owned(),
    ]);
    if !all.iter().any(|c| path_of(c) == "AndroidManifest.xml") {
        limitations.push("No root AndroidManifest.xml occurrence was observed. The APK family comes from the .apk suffix of a ZIP archive, so these bytes may not be an APK.".into());
    }
    if bridge_partial {
        limitations.push(format!(
            "Bridge candidate pairs exceeded the projection safety budget; {} hypotheses are omitted. Component arrays still include every component from the supplied inventory pages.",
            bridge_coverage["omitted_candidates"]
        ));
    }
    if !unavailable.is_empty() {
        limitations.push("Some inventoried occurrences have no authenticated content identity. Their paths and limitations are retained in unavailable_components; component absence is unknown.".into());
    }
    let budget_complete = bridge_coverage["status"] == "complete" && unavailable.is_empty();
    let result = json!({
        "root_sha256": inventory.root_sha256(),
        "root_format": "apk",
        "source_evidence_ids": projection::source_ids(parsed),
        "components": {
            "manifests": manifests,
            "resources": resources,
            "dex": dex,
            "jvm_classes": jvm_classes,
            "native_libraries": native_libraries,
            "javascript": javascript,
            "signing": signing,
        },
        "unavailable_components": unavailable,
        "runtime_families": families.into_iter().collect::<Vec<_>>(),
        "bridge_candidates": bridges,
        "bridge_candidate_coverage": bridge_coverage,
        "coverage": projection::coverage(inventory, budget_complete),
        "limitations": limitations,
    });
    projection::identified(result, "adp", "Android application projection")
}

/// `(?:^|\/)<name>$` (case-sensitive).
fn segment_named(path: &str, name: &str) -> bool {
    path == name
        || path
            .strip_suffix(name)
            .is_some_and(|prefix| prefix.ends_with('/'))
}

fn bridge_basis(path: &str) -> &'static str {
    match projection::native_runtime_convention(path) {
        Some("react-native") => "react-native-convention",
        Some("flutter") => "flutter-convention",
        Some("unity") => "unity-convention",
        _ if projection::library_layout(path, "lib", "lib", ".so") => "jni-library-convention",
        _ => "managed-and-native-content",
    }
}
