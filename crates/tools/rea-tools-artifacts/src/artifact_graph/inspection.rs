//! Provider-neutral inspection projection over one inventory Evidence record.
//!
//! Compatibility owner: `src/domain/artifactInspection.ts`
//! (`createArtifactInspection`). The nested inventory graph stays inside the
//! substep's Evidence; this result restates only the root manifest observation,
//! integrity observations/contradictions, bounded hypotheses, next probes and
//! unexplored branches.
use super::graph::{digest_value, unique_sorted};
use crate::artifact_graph::graph::ArtifactInventoryResult;
use rea_core::evidence::envelope::Evidence;
use serde_json::{Map, Value, json};

/// Project one successful inventory Evidence record into an inspection report.
pub fn create_artifact_inspection(
    inventory_evidence: &Evidence,
    inventory: &ArtifactInventoryResult,
) -> Value {
    let evidence_id = inventory_evidence.id().to_owned();
    let evidence_value = inventory_evidence.value().clone();

    let observations = all_observations(inventory, &evidence_id);
    let hypotheses = all_hypotheses(inventory, &evidence_id);
    let next_probes = probes_for(inventory);
    let branches = all_unexplored_branches(inventory, &evidence_id, &next_probes);
    let contradictions = contradictions(inventory, &evidence_id);

    let substep_semantic = json!({
        "operation": "inventory_artifact",
        "evidence_id": evidence_id,
    });
    let substep = json!({
        "substep_id": format!("ais_{}", digest_value(&substep_semantic)),
        "operation": "inventory_artifact",
        "status": "completed",
        "evidence_id": evidence_id,
        "evidence": evidence_value,
    });

    let coverage_status = "complete-within-substeps";
    let coverage = json!({
        "status": coverage_status,
        "substeps_completed": 1,
        "observations_retained": observations.len(),
        "observations_omitted": 0,
        "hypotheses_retained": hypotheses.len(),
        "hypotheses_omitted": 0,
        "unexplored_branches_retained": branches.len(),
        "unexplored_branches_omitted": 0,
        "next_probes_retained": next_probes.len(),
        "next_probes_omitted": 0,
    });

    let mut limitations: Vec<String> = inventory.limitations.clone();
    limitations.push(
        "Inspection derives bounded static hypotheses and next probes; it does not execute the artifact or claim format-specific semantics.".to_owned(),
    );
    let limitations = unique_sorted(limitations);

    let subject = json!({
        "manifest_id": inventory.manifest.manifest_id,
        "root_artifact_id": inventory.manifest.root_artifact_id,
        "root_sha256": inventory.manifest.root_sha256,
        "root_format": inventory.manifest.root_format,
    });

    let mut semantic = Map::new();
    semantic.insert("subject".into(), subject);
    semantic.insert("substeps".into(), Value::Array(vec![substep]));
    semantic.insert("observations".into(), Value::Array(observations));
    semantic.insert("hypotheses".into(), Value::Array(hypotheses));
    semantic.insert("contradictions".into(), Value::Array(contradictions));
    semantic.insert("unexplored_branches".into(), Value::Array(branches));
    semantic.insert("next_probes".into(), Value::Array(next_probes));
    semantic.insert("coverage".into(), coverage);
    semantic.insert(
        "evidence_links".into(),
        Value::Array(vec![Value::String(evidence_id.clone())]),
    );
    semantic.insert(
        "limitations".into(),
        Value::Array(limitations.into_iter().map(Value::String).collect()),
    );

    let semantic_value = Value::Object(semantic.clone());
    let inspection_id = format!("ai_{}", digest_value(&semantic_value));

    let mut result = Map::new();
    result.insert("inspection_id".into(), Value::String(inspection_id));
    for (key, value) in semantic {
        result.insert(key, value);
    }
    Value::Object(result)
}

fn observation(kind: &str, subject: &str, value: Value, evidence_id: &str) -> Value {
    let semantic = json!({
        "kind": kind,
        "subject": subject,
        "value": value,
        "evidence_id": evidence_id,
    });
    let observation_id = format!("aio_{}", digest_value(&semantic));
    let mut out = Map::new();
    out.insert("observation_id".into(), Value::String(observation_id));
    if let Value::Object(object) = semantic {
        for (key, value) in object {
            out.insert(key, value);
        }
    }
    Value::Object(out)
}

fn all_observations(inventory: &ArtifactInventoryResult, evidence_id: &str) -> Vec<Value> {
    let mut out = Vec::new();
    out.push(observation(
        "root-manifest",
        &inventory.manifest.root_artifact_id,
        serde_json::to_value(&inventory.manifest).expect("manifest serializes"),
        evidence_id,
    ));
    for contradiction in &inventory.integrity_contradictions {
        out.push(observation(
            "integrity",
            &contradiction.contradiction_id,
            serde_json::to_value(contradiction).expect("contradiction serializes"),
            evidence_id,
        ));
    }
    out
}

fn all_hypotheses(inventory: &ArtifactInventoryResult, evidence_id: &str) -> Vec<Value> {
    let format = inventory.manifest.root_format.as_str();
    let statements: Vec<&str> = if format == "pe" {
        vec![
            "The PE artifact may contain managed CLI metadata or native code; inventory bytes alone do not distinguish them.",
        ]
    } else if format == "asar" || format == "javascript-bundle" {
        vec!["The artifact may contain a recoverable JavaScript application graph."]
    } else {
        Vec::new()
    };
    statements
        .into_iter()
        .map(|statement| {
            let semantic = json!({
                "statement": statement,
                "confidence": "low",
                "basis_evidence_ids": [evidence_id],
                "limitation": "Format classification proposes a bounded follow-up; it is not semantic proof.",
            });
            let hypothesis_id = format!("aih_{}", digest_value(&semantic));
            let mut out = Map::new();
            out.insert("hypothesis_id".into(), Value::String(hypothesis_id));
            if let Value::Object(object) = semantic {
                for (key, value) in object {
                    out.insert(key, value);
                }
            }
            Value::Object(out)
        })
        .collect()
}

fn contradictions(inventory: &ArtifactInventoryResult, evidence_id: &str) -> Vec<Value> {
    inventory
        .integrity_contradictions
        .iter()
        .map(|value| {
            let semantic = json!({
                "statement": format!("Declared integrity for {} contradicts observed bytes.", value.logical_path),
                "occurrence_id": value.occurrence_id,
                "declared_sha256": value.declared_sha256,
                "observed_sha256": value.observed_sha256,
                "evidence_id": evidence_id,
            });
            let contradiction_id = format!("aic_{}", digest_value(&semantic));
            let mut out = Map::new();
            out.insert("contradiction_id".into(), Value::String(contradiction_id));
            if let Value::Object(object) = semantic {
                for (key, value) in object {
                    out.insert(key, value);
                }
            }
            Value::Object(out)
        })
        .collect()
}

fn probe(operation: &str, rationale: &str, authority: &str) -> Value {
    json!({
        "operation": operation,
        "rationale": rationale,
        "authority": authority,
    })
}

fn probes_for_format(format: &str) -> Vec<Value> {
    if format == "asar" || format == "javascript-bundle" {
        return vec![probe(
            "analyze_javascript_application",
            "Recover bounded JavaScript modules, source maps, Electron boundaries, and application relationships.",
            "ast-static-analysis",
        )];
    }
    if format == "pe" {
        return vec![
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
        ];
    }
    if ["mach-o", "mach-o-universal", "elf"].contains(&format) {
        return vec![probe(
            "open_binary",
            "Bind one deep native provider before function-level analysis.",
            "native-analysis-provider",
        )];
    }
    if format == "plist" {
        return vec![probe(
            "inspect_plist",
            "Parse property-list values without executing the artifact.",
            "artifact-bytes",
        )];
    }
    Vec::new()
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

fn probes_for(inventory: &ArtifactInventoryResult) -> Vec<Value> {
    let format = inventory.manifest.root_format.as_str();
    if format == "directory" {
        return directory_probes(inventory);
    }
    probes_for_format(format)
}

fn directory_probes(inventory: &ArtifactInventoryResult) -> Vec<Value> {
    let mut present: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for occurrence in &inventory.occurrences {
        if occurrence.entry_kind == "symlink" && occurrence.artifact_format == "javascript-bundle" {
            continue;
        }
        present.insert(occurrence.artifact_format.as_str());
    }
    let members: Vec<&str> = DIRECTORY_MEMBER_FORMATS
        .into_iter()
        .filter(|format| present.contains(format))
        .collect();
    let probes: Vec<Value> = members.into_iter().flat_map(probes_for_format).collect();
    // Deduplicate by operation, keeping first occurrence.
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    probes
        .into_iter()
        .filter(|probe| {
            let operation = probe
                .get("operation")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            seen.insert(operation)
        })
        .collect()
}

fn branch(reason: &str, detail: &str, next_probe: Option<Value>, evidence_id: &str) -> Value {
    let semantic = json!({
        "reason": reason,
        "detail": detail,
        "next_probe": next_probe,
        "evidence_id": evidence_id,
    });
    let branch_id = format!("aib_{}", digest_value(&semantic));
    let mut out = Map::new();
    out.insert("branch_id".into(), Value::String(branch_id));
    if let Value::Object(object) = semantic {
        for (key, value) in object {
            out.insert(key, value);
        }
    }
    Value::Object(out)
}

fn all_unexplored_branches(
    inventory: &ArtifactInventoryResult,
    evidence_id: &str,
    next_probes: &[Value],
) -> Vec<Value> {
    let mut branches = Vec::new();
    for probe in next_probes {
        let operation = probe.get("operation").and_then(Value::as_str).unwrap_or("");
        branches.push(branch(
            "format-specific-analysis-required",
            &format!("{operation} was not run by provider-neutral artifact inspection."),
            Some(probe.clone()),
            evidence_id,
        ));
    }
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
