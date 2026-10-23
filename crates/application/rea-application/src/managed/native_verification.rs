//! Provider-neutral verification of managed P/Invoke declarations.
//!
//! This workflow compares declared import names with symbols already present in
//! authenticated native Evidence. It never treats a managed token or RVA as a
//! native address.

use rea_core::canonical_json;
use serde_json::{Value, json};
use std::{collections::HashSet, path::Path};

pub fn verify(input: &Value) -> Result<Value, String> {
    let managed = Boundary::parse(
        input
            .get("managed_boundaries")
            .ok_or("managed_boundaries is required")?,
    )?;
    let observations = input
        .get("native_observations")
        .and_then(Value::as_array)
        .ok_or("native_observations must be a non-empty array")?;
    if observations.is_empty() {
        return Err("native_observations must be a non-empty array".into());
    }

    let mut symbols = Vec::new();
    let mut accepted = 0usize;
    let mut unsupported = 0usize;
    let mut observation_ids = HashSet::new();
    for observation in observations {
        let observation_id = observation
            .get("evidence_id")
            .and_then(Value::as_str)
            .ok_or("Native observation has no evidence_id")?;
        if !observation_ids.insert(observation_id) {
            return Err("Native observation Evidence IDs must be unique".into());
        }
        if observation.get("evidence_id").and_then(Value::as_str)
            == Some(managed.evidence_id.as_str())
        {
            return Err(
                "Native observation Evidence must be distinct from managed boundary Evidence"
                    .into(),
            );
        }
        match collect_symbols(observation) {
            Some(items) => {
                accepted += 1;
                symbols.extend(items);
            }
            None => unsupported += 1,
        }
    }

    let pinvoke_imports = managed
        .pinvoke_imports
        .iter()
        .map(|item| verify_import(item, &managed.evidence_id, &symbols, accepted))
        .collect::<Result<Vec<_>, _>>()?;
    let counts = |status: &str| {
        pinvoke_imports
            .iter()
            .filter(|item| item["status"] == status)
            .count()
    };
    let native_body_unresolved = managed
        .native_implementations
        .iter()
        .filter(|implementation| {
            implementation.get("boundary_kind").and_then(Value::as_str) != Some("pinvoke")
        })
        .count();
    let mut limitations = vec![
        Value::String(
            "P/Invoke verification checks declared import names against supplied native export or function-name Evidence only."
                .into(),
        ),
        Value::String(
            "A matching native symbol verifies that a candidate export/function was observed; it does not prove CLR binding, marshaling behavior, call reachability, or runtime loading."
                .into(),
        ),
        Value::String(
            "Missing supplied native symbols are reported as unresolved, not proof that a dependency cannot exist."
                .into(),
        ),
        Value::String(
            "Managed metadata tokens and method RVAs are not interpreted as native addresses."
                .into(),
        ),
    ];
    if managed.coverage_state != "complete" {
        limitations.push(Value::String(
            "Managed boundary input is partial or unavailable.".into(),
        ));
    }
    if unsupported > 0 {
        limitations.push(Value::String(
            "Some native Evidence operations were unsupported by this workflow.".into(),
        ));
    }
    let mut evidence_links = vec![Value::String(managed.evidence_id.clone())];
    evidence_links.extend(
        observations
            .iter()
            .filter_map(|item| item.get("evidence_id").cloned()),
    );
    let without_id = json!({
        "algorithm": {"name":"rea-managed-native-verification","token_identity":"build-local","token_to_address_mapping":"not-inferred"},
        "managed_boundary": {
            "evidence_id": managed.evidence_id,
            "artifact_sha256": managed.artifact_sha256,
            "artifact_path": managed.artifact_path,
            "mvid": managed.mvid,
            "metadata_status": managed.metadata_status,
            "pinvoke_imports_total": managed.pinvoke_imports.len(),
            "native_implementations_total": managed.native_implementations.len(),
            "coverage_state": managed.coverage_state
        },
        "native_observations": {"total": observations.len(), "accepted": accepted, "unsupported": unsupported, "symbols": symbols.len()},
        "summary": {"verified":counts("verified"),"inferred":counts("inferred"),"unresolved":counts("unresolved"),"contradicted":counts("contradicted"),"native_body_unresolved":native_body_unresolved},
        "pinvoke_imports": pinvoke_imports,
        "native_implementations": {"unresolved":native_body_unresolved,"reason":"Managed metadata tokens and RVAs are not translated to native provider addresses by this workflow; C++/CLI, ReadyToRun, and native-body mappings require explicit provider-supported bridge evidence."},
        "coverage": {"status": if managed.coverage_state == "complete" && unsupported == 0 {"complete-within-inputs"} else {"partial"}},
        "evidence_links": evidence_links,
        "limitations": limitations
    });
    let mut output = without_id;
    output["verification_id"] = Value::String(format!("mnv_{}", digest(&output)?));
    Ok(output)
}

#[derive(Debug)]
struct Boundary {
    evidence_id: String,
    artifact_sha256: Value,
    artifact_path: String,
    mvid: Value,
    metadata_status: String,
    coverage_state: String,
    pinvoke_imports: Vec<Value>,
    native_implementations: Vec<Value>,
}

impl Boundary {
    fn parse(evidence: &Value) -> Result<Self, String> {
        if evidence.get("operation").and_then(Value::as_str)
            != Some("inspect_managed_native_boundaries")
        {
            return Err("Evidence operation is not inspect_managed_native_boundaries".into());
        }
        let result = evidence
            .get("normalized_result")
            .or_else(|| evidence.get("result"))
            .ok_or("Managed boundary Evidence has no normalized_result")?;
        let artifact = result
            .get("artifact")
            .ok_or("Managed boundary has no artifact")?;
        let coverage = result
            .get("coverage")
            .ok_or("Managed boundary has no coverage")?;
        Ok(Self {
            evidence_id: evidence
                .get("evidence_id")
                .and_then(Value::as_str)
                .ok_or("Managed boundary has no evidence_id")?
                .to_owned(),
            artifact_sha256: artifact
                .get("sha256")
                .cloned()
                .ok_or("Managed boundary has no artifact SHA-256")?,
            artifact_path: artifact
                .get("path")
                .and_then(Value::as_str)
                .filter(|path| !path.is_empty())
                .ok_or("Managed boundary has no artifact path")?
                .to_owned(),
            mvid: result
                .pointer("/module/mvid")
                .cloned()
                .unwrap_or(Value::Null),
            metadata_status: result
                .pointer("/metadata/status")
                .and_then(Value::as_str)
                .ok_or("Managed boundary has no metadata status")?
                .to_owned(),
            coverage_state: coverage
                .get("state")
                .and_then(Value::as_str)
                .ok_or("Managed boundary has no coverage state")?
                .to_owned(),
            pinvoke_imports: result
                .get("pinvoke_imports")
                .and_then(Value::as_array)
                .cloned()
                .ok_or("Managed boundary has no pinvoke_imports")?,
            native_implementations: result
                .get("native_implementations")
                .and_then(Value::as_array)
                .cloned()
                .ok_or("Managed boundary has no native_implementations")?,
        })
    }
}

fn collect_symbols(evidence: &Value) -> Option<Vec<Value>> {
    let operation = evidence.get("operation").and_then(Value::as_str)?;
    let result = evidence
        .get("normalized_result")
        .or_else(|| evidence.get("result"))?;
    let module_name = evidence
        .pointer("/subject/name")
        .cloned()
        .unwrap_or(Value::Null);
    let module_path = evidence
        .pointer("/subject/local_path")
        .cloned()
        .unwrap_or(Value::Null);
    match operation {
        "inspect_macho" => result.pointer("/exports/items").and_then(Value::as_array).map(|items| items.iter().filter_map(|item| symbol(evidence, item.get("name")?.as_str()?, item.get("address").cloned().unwrap_or(Value::Null), module_name.clone(), module_path.clone(), "macho-export")).collect()),
        "analyze_function" => result.pointer("/procedure/name").and_then(Value::as_str).map(|name| vec![json!({"evidence_id":evidence.get("evidence_id"),"operation":operation,"name":name,"address":result.pointer("/procedure/address").cloned().unwrap_or(Value::Null),"module_name":module_name,"module_path":module_path,"source":"function-dossier"})]),
        _ => None,
    }
}

fn symbol(
    evidence: &Value,
    name: &str,
    address: Value,
    module_name: Value,
    module_path: Value,
    source: &str,
) -> Option<Value> {
    Some(
        json!({"evidence_id":evidence.get("evidence_id"),"operation":evidence.get("operation"),"name":name,"address":address,"module_name":module_name,"module_path":module_path,"source":source}),
    )
}

fn verify_import(
    item: &Value,
    managed_id: &str,
    symbols: &[Value],
    accepted: usize,
) -> Result<Value, String> {
    let import_name = item
        .get("import_name")
        .and_then(Value::as_str)
        .ok_or("P/Invoke import has no import_name")?;
    let candidates = symbols
        .iter()
        .filter(|symbol| {
            candidate_names(item)
                .iter()
                .any(|name| normalized_symbol_name(symbol).as_deref() == Some(name.as_str()))
        })
        .cloned()
        .collect::<Vec<_>>();
    let scope = item
        .get("import_scope_name")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty());
    let scope_known = scope.is_some();
    let exact = candidates.iter().find(|candidate| {
        normalized_symbol_name(candidate).as_deref() == Some(import_name)
            && module_matches(scope, candidate)
    });
    let decorated = candidates
        .iter()
        .find(|candidate| module_matches(scope, candidate));
    let selected = exact
        .or(decorated)
        .or_else(|| {
            if scope_known {
                candidates
                    .iter()
                    .find(|candidate| !has_module_identity(candidate))
            } else {
                None
            }
        })
        .or_else(|| candidates.first());

    let (status, basis, confidence, matched) = if candidates.is_empty() {
        (
            "unresolved",
            if accepted > 0 {
                "no-native-candidate"
            } else {
                "unsupported-native-evidence"
            },
            "unknown",
            Value::Null,
        )
    } else if let Some(exact) = exact {
        (
            "verified",
            if exact["source"] == "macho-export" {
                "exact-export-name"
            } else {
                "exact-function-name"
            },
            "observed",
            exact.clone(),
        )
    } else if let Some(decorated) = decorated {
        (
            "inferred",
            "decorated-name-candidate",
            "inferred",
            decorated.clone(),
        )
    } else if !scope_known || !selected.map(has_module_identity).unwrap_or(false) {
        (
            "unresolved",
            "module-identity-unknown",
            "unknown",
            selected.cloned().unwrap_or(Value::Null),
        )
    } else {
        (
            "contradicted",
            "module-mismatch",
            "unknown",
            selected.cloned().unwrap_or(Value::Null),
        )
    };
    let mut limitations = Vec::new();
    if !scope_known {
        limitations.push(Value::String(
            "Managed declaration does not name an import scope/module.".into(),
        ));
    }
    match (status, basis) {
        ("inferred", _) => limitations.push(Value::String(
            "Native symbol matched a decorated candidate rather than the exact declared import name."
                .into(),
        )),
        ("contradicted", _) => limitations.push(Value::String(
            "A symbol name candidate exists, but the supplied native Evidence module identity does not match the managed import scope."
                .into(),
        )),
        ("unresolved", "module-identity-unknown") => limitations.push(Value::String(
            "A native name candidate exists, but a required module identity is unavailable; module correspondence is unknown."
                .into(),
        )),
        ("unresolved", _) => limitations.push(Value::String(
            "No supplied native export/function Evidence matched this declared import.".into(),
        )),
        _ => {}
    }
    let candidate_ids = candidates
        .iter()
        .filter_map(|candidate| candidate.get("evidence_id").cloned())
        .collect::<Vec<_>>();
    let mut evidence_links = vec![Value::String(managed_id.into())];
    for candidate_id in candidate_ids {
        if !evidence_links.contains(&candidate_id) {
            evidence_links.push(candidate_id);
        }
    }
    Ok(
        json!({"item_id":format!("mnv_pinvoke_{}",digest(&json!({"managedEvidenceId":managed_id,"token":item.get("token"),"importName":import_name,"importScope":item.get("import_scope_name"),"candidates":candidates}))?),"managed":{"token":item.get("token"),"member_token":item.get("member_token").cloned().unwrap_or(Value::Null),"member_name":item.get("member_name").cloned().unwrap_or(Value::Null),"import_name":import_name,"import_scope_name":item.get("import_scope_name").cloned().unwrap_or(Value::Null),"no_mangle":item.get("no_mangle").and_then(Value::as_bool).unwrap_or(false),"char_set":item.get("char_set").and_then(Value::as_str).unwrap_or("unknown"),"call_convention":item.get("call_convention").and_then(Value::as_str).unwrap_or("unknown"),"declaration_verification":item.get("verification").and_then(Value::as_str).unwrap_or("managed-declaration-only")},"status":status,"basis":basis,"confidence":confidence,"matched_native":matched,"candidates":candidates,"evidence_links":evidence_links,"limitations":limitations}),
    )
}

fn candidate_names(item: &Value) -> Vec<String> {
    let name = item
        .get("import_name")
        .and_then(Value::as_str)
        .unwrap_or("");
    let mut values = vec![name.to_owned()];
    if item.get("no_mangle").and_then(Value::as_bool) != Some(true) {
        match item.get("char_set").and_then(Value::as_str) {
            Some("unicode") => values.push(format!("{name}W")),
            Some("ansi") => values.push(format!("{name}A")),
            _ => {}
        }
        if item.get("call_convention").and_then(Value::as_str) == Some("stdcall") {
            values.push(format!("_{name}"));
            values.push(format!("_{name}@0"));
        }
    }
    values
}

fn module_matches(scope: Option<&str>, symbol: &Value) -> bool {
    let Some(scope) = scope else { return false };
    let expected = normalize_module(scope);
    [symbol.get("module_name"), symbol.get("module_path")]
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .any(|value| {
            native_module_identities(value)
                .iter()
                .any(|identity| identity == &expected)
        })
}

fn normalized_symbol_name(symbol: &Value) -> Option<String> {
    let name = symbol.get("name").and_then(Value::as_str)?;
    if symbol.get("source").and_then(Value::as_str) == Some("macho-export") {
        Some(name.strip_prefix('_').unwrap_or(name).to_owned())
    } else {
        Some(name.to_owned())
    }
}

fn has_module_identity(symbol: &Value) -> bool {
    [symbol.get("module_name"), symbol.get("module_path")]
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .any(|value| !normalize_module(value).is_empty())
}

fn native_module_identities(value: &str) -> Vec<String> {
    let normalized = normalize_module(value);
    let mut identities = vec![normalized.clone()];
    let lower = value.to_lowercase();
    if (lower.ends_with(".dylib") || lower.ends_with(".so")) && normalized.starts_with("lib") {
        identities.push(normalized.trim_start_matches("lib").to_owned());
    }
    identities
}

fn normalize_module(value: &str) -> String {
    let name = Path::new(value)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(value)
        .to_lowercase();
    [".dylib", ".so", ".dll", ".node", ".exe"]
        .iter()
        .find_map(|suffix| name.strip_suffix(suffix))
        .unwrap_or(&name)
        .to_owned()
}

fn digest(value: &Value) -> Result<String, String> {
    canonical_json::digest(value).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::verify;
    use serde_json::json;

    fn managed() -> serde_json::Value {
        json!({
            "evidence_id": "ev_managed",
            "operation": "inspect_managed_native_boundaries",
            "normalized_result": {
                "artifact": {"sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "path": "/tmp/a.dll"},
                "module": {"mvid": null},
                "metadata": {"status": "complete"},
                "coverage": {"state": "complete"},
                "pinvoke_imports": [{
                    "token": "0x06000001",
                    "member_token": "0x06000001",
                    "member_name": "NativeOpen",
                    "import_name": "NativeOpen",
                    "import_scope_name": "native",
                    "no_mangle": false,
                    "char_set": "not-specified",
                    "call_convention": "winapi",
                    "verification": "managed-declaration-only"
                }],
                "native_implementations": []
            }
        })
    }

    #[test]
    fn verifies_exact_native_export_and_links_evidence() {
        let output = verify(&json!({
            "managed_boundaries": managed(),
            "native_observations": [{
                "evidence_id": "ev_native",
                "operation": "inspect_macho",
                "subject": {"name": "native.dylib", "local_path": "/tmp/native.dylib"},
                "normalized_result": {"exports": {"items": [{"name": "NativeOpen", "address": "0x1000"}]}}
            }]
        })).expect("verification");

        assert_eq!(output["summary"]["verified"], 1);
        assert_eq!(output["pinvoke_imports"][0]["status"], "verified");
        assert_eq!(
            output["pinvoke_imports"][0]["matched_native"]["evidence_id"],
            "ev_native"
        );
    }

    #[test]
    fn reports_unsupported_native_observation_as_unresolved() {
        let output = verify(&json!({
            "managed_boundaries": managed(),
            "native_observations": [{
                "evidence_id": "ev_unknown",
                "operation": "inspect_elf",
                "normalized_result": {}
            }]
        }))
        .expect("verification");

        assert_eq!(output["summary"]["unresolved"], 1);
        assert_eq!(
            output["pinvoke_imports"][0]["basis"],
            "unsupported-native-evidence"
        );
        assert_eq!(output["coverage"]["status"], "partial");
    }

    #[test]
    fn classifies_decorated_candidates_as_inferred() {
        let mut managed = managed();
        managed["normalized_result"]["pinvoke_imports"][0]["call_convention"] =
            serde_json::Value::String("stdcall".into());
        let output = verify(&json!({
            "managed_boundaries": managed,
            "native_observations": [{
                "evidence_id": "ev_native",
                "operation": "inspect_macho",
                "subject": {"name": "native.dylib"},
                "normalized_result": {"exports": {"items": [{"name": "_NativeOpen", "address": "0x1000"}]}}
            }]
        })).expect("verification");

        assert_eq!(output["summary"]["inferred"], 1);
        assert_eq!(
            output["pinvoke_imports"][0]["basis"],
            "decorated-name-candidate"
        );
    }
}
