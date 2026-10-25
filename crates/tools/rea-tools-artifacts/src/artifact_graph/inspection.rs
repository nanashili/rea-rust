//! Lossless provider-neutral inspection projection.
use super::graph::{ArtifactInventoryResult, unique_sorted};
use rea_application::javascript::graph::json::{Json, Obj};
use rea_core::evidence::record::EvidenceRecord;

fn serialized<T: serde::Serialize>(value: &T) -> Json {
    let text = serde_json::to_string(value).expect("owned artifact values serialize");
    rea_application::javascript::graph::json::parse(&text).expect("serialized artifact JSON parses")
}

fn string_array(values: impl IntoIterator<Item = String>) -> Json {
    Json::Array(values.into_iter().map(Json::from).collect())
}

fn object_id(prefix: &str, semantic: &Json) -> Json {
    format!("{prefix}{}", semantic.digest()).into()
}

pub fn create_artifact_inspection(
    inventory_evidence: &EvidenceRecord,
    inventory: &ArtifactInventoryResult,
) -> Json {
    let evidence_id = inventory_evidence.evidence_id();
    let observations = all_observations(inventory, evidence_id);
    let hypotheses = all_hypotheses(inventory, evidence_id);
    let next_probes = probes_for(inventory);
    let branches = all_unexplored_branches(inventory, evidence_id, &next_probes);
    let contradictions = contradictions(inventory, evidence_id);
    let substep_semantic: Json = Obj::new()
        .with("operation", "inventory_artifact")
        .with("evidence_id", evidence_id)
        .into();
    let substep = Obj::new()
        .with("substep_id", object_id("ais_", &substep_semantic))
        .with("operation", "inventory_artifact")
        .with("status", "completed")
        .with("evidence_id", evidence_id)
        .with(
            "evidence",
            rea_application::javascript::graph::json::parse(inventory_evidence.raw().get())
                .expect("authenticated inventory Evidence parses"),
        );
    let coverage = Obj::new()
        .with("status", "complete-within-substeps")
        .with("substeps_completed", 1usize)
        .with("observations_retained", observations.len())
        .with("observations_omitted", 0usize)
        .with("hypotheses_retained", hypotheses.len())
        .with("hypotheses_omitted", 0usize)
        .with("unexplored_branches_retained", branches.len())
        .with("unexplored_branches_omitted", 0usize)
        .with("next_probes_retained", next_probes.len())
        .with("next_probes_omitted", 0usize);
    let mut limitations = inventory.limitations.clone();
    limitations.push("Inspection derives bounded static hypotheses and next probes; it does not execute the artifact or claim format-specific semantics.".to_owned());
    let semantic = Obj::new()
        .with(
            "subject",
            Obj::new()
                .with("manifest_id", inventory.manifest.manifest_id.clone())
                .with(
                    "root_artifact_id",
                    inventory.manifest.root_artifact_id.clone(),
                )
                .with("root_sha256", inventory.manifest.root_sha256.clone())
                .with("root_format", inventory.manifest.root_format.clone()),
        )
        .with("substeps", vec![Json::from(substep)])
        .with("observations", observations)
        .with("hypotheses", hypotheses)
        .with("contradictions", contradictions)
        .with("unexplored_branches", branches)
        .with("next_probes", next_probes)
        .with("coverage", coverage)
        .with("evidence_links", vec![Json::from(evidence_id)])
        .with("limitations", string_array(unique_sorted(limitations)));
    let inspection_id = format!("ai_{}", Json::from(semantic.clone()).digest());
    let mut result = semantic;
    result.set("inspection_id", inspection_id);
    result.into()
}

fn observation(kind: &str, subject: &str, value: Json, evidence_id: &str) -> Json {
    let semantic: Json = Obj::new()
        .with("kind", kind)
        .with("subject", subject)
        .with("value", value)
        .with("evidence_id", evidence_id)
        .into();
    Obj::new()
        .with("observation_id", object_id("aio_", &semantic))
        .with("kind", kind)
        .with("subject", subject)
        .with("value", semantic.at("value"))
        .with("evidence_id", evidence_id)
        .into()
}

fn all_observations(inventory: &ArtifactInventoryResult, evidence_id: &str) -> Vec<Json> {
    let mut out = vec![observation(
        "root-manifest",
        &inventory.manifest.root_artifact_id,
        serialized(&inventory.manifest),
        evidence_id,
    )];
    out.extend(
        inventory
            .integrity_contradictions
            .iter()
            .map(|contradiction| {
                observation(
                    "integrity",
                    &contradiction.contradiction_id,
                    serialized(contradiction),
                    evidence_id,
                )
            }),
    );
    out
}

fn all_hypotheses(inventory: &ArtifactInventoryResult, evidence_id: &str) -> Vec<Json> {
    let statements = match inventory.manifest.root_format.as_str() {
        "pe" => vec![
            "The PE artifact may contain managed CLI metadata or native code; inventory bytes alone do not distinguish them.",
        ],
        "asar" | "javascript-bundle" => {
            vec!["The artifact may contain a recoverable JavaScript application graph."]
        }
        _ => Vec::new(),
    };
    statements
        .into_iter()
        .map(|statement| {
            let semantic: Json = Obj::new()
                .with("statement", statement)
                .with("confidence", "low")
                .with("basis_evidence_ids", vec![Json::from(evidence_id)])
                .with(
                    "limitation",
                    "Format classification proposes a bounded follow-up; it is not semantic proof.",
                )
                .into();
            Obj::new()
                .with("hypothesis_id", object_id("aih_", &semantic))
                .with("statement", statement)
                .with("confidence", "low")
                .with("basis_evidence_ids", vec![Json::from(evidence_id)])
                .with(
                    "limitation",
                    "Format classification proposes a bounded follow-up; it is not semantic proof.",
                )
                .into()
        })
        .collect()
}

fn contradictions(inventory: &ArtifactInventoryResult, evidence_id: &str) -> Vec<Json> {
    inventory
        .integrity_contradictions
        .iter()
        .map(|value| {
            let statement = rea_core::JsString::from("Declared integrity for ")
                .concat(&value.logical_path)
                .concat_str(" contradicts observed bytes.");
            let semantic: Json = Obj::new()
                .with("statement", statement.clone())
                .with("occurrence_id", value.occurrence_id.clone())
                .with("declared_sha256", value.declared_sha256.clone())
                .with("observed_sha256", value.observed_sha256.clone())
                .with("evidence_id", evidence_id)
                .into();
            Obj::new()
                .with("contradiction_id", object_id("aic_", &semantic))
                .with("statement", statement)
                .with("occurrence_id", value.occurrence_id.clone())
                .with("declared_sha256", value.declared_sha256.clone())
                .with("observed_sha256", value.observed_sha256.clone())
                .with("evidence_id", evidence_id)
                .into()
        })
        .collect()
}

fn probe(operation: &str, rationale: &str, authority: &str) -> Json {
    Obj::new()
        .with("operation", operation)
        .with("rationale", rationale)
        .with("authority", authority)
        .into()
}
fn probes_for_format(format: &str) -> Vec<Json> {
    match format {
        "asar" | "javascript-bundle" => vec![probe(
            "analyze_javascript_application",
            "Recover bounded JavaScript modules, source maps, Electron boundaries, and application relationships.",
            "ast-static-analysis",
        )],
        "pe" => vec![
            probe(
                "inspect_managed_artifact",
                "Check execution-free CLI metadata before choosing a deep native provider.",
                "managed-static-analysis",
            ),
            probe(
                "open_binary",
                "Open as native code only when managed inspection reports a native or mixed boundary.",
                "native-analysis-provider",
            ),
        ],
        "mach-o" | "mach-o-universal" | "elf" => vec![probe(
            "open_binary",
            "Bind one deep native provider before function-level analysis.",
            "native-analysis-provider",
        )],
        "plist" => vec![probe(
            "inspect_plist",
            "Parse property-list values without executing the artifact.",
            "artifact-bytes",
        )],
        _ => Vec::new(),
    }
}
const DIRECTORY_MEMBER_FORMATS: [&str; 7] = [
    "asar",
    "javascript-bundle",
    "mach-o-universal",
    "mach-o",
    "elf",
    "pe",
    "plist",
];
fn probes_for(inventory: &ArtifactInventoryResult) -> Vec<Json> {
    if inventory.manifest.root_format != "directory" {
        return probes_for_format(&inventory.manifest.root_format);
    }
    let mut present = std::collections::HashSet::new();
    for occurrence in &inventory.occurrences {
        if occurrence.entry_kind != "symlink" || occurrence.artifact_format != "javascript-bundle" {
            present.insert(occurrence.artifact_format.as_str());
        }
    }
    let mut seen = std::collections::HashSet::new();
    DIRECTORY_MEMBER_FORMATS
        .iter()
        .filter(|format| present.contains(**format))
        .flat_map(|format| probes_for_format(format))
        .filter(|probe| {
            seen.insert(
                probe
                    .get("operation")
                    .and_then(Json::as_str)
                    .unwrap_or("")
                    .to_owned(),
            )
        })
        .collect()
}
fn branch(reason: &str, detail: &str, next_probe: Option<Json>, evidence_id: &str) -> Json {
    let semantic: Json = Obj::new()
        .with("reason", reason)
        .with("detail", detail)
        .with("next_probe", next_probe.clone())
        .with("evidence_id", evidence_id)
        .into();
    Obj::new()
        .with("branch_id", object_id("aib_", &semantic))
        .with("reason", reason)
        .with("detail", detail)
        .with("next_probe", next_probe)
        .with("evidence_id", evidence_id)
        .into()
}
fn all_unexplored_branches(
    inventory: &ArtifactInventoryResult,
    evidence_id: &str,
    next_probes: &[Json],
) -> Vec<Json> {
    let mut branches = next_probes
        .iter()
        .map(|probe| {
            let operation = probe.get("operation").and_then(Json::as_str).unwrap_or("");
            branch(
                "format-specific-analysis-required",
                &format!("{operation} was not run by provider-neutral artifact inspection."),
                Some(probe.clone()),
                evidence_id,
            )
        })
        .collect::<Vec<_>>();
    if inventory.manifest.root_format == "unknown" {
        branches.push(branch(
            "unknown-format",
            "Artifact bytes did not match an admitted format classifier.",
            None,
            evidence_id,
        ));
    }
    branches
}
