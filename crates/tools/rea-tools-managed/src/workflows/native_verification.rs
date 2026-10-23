//! `verify_managed_native_boundaries`.
//!
//! Compatibility owners:
//! `src/server/registerManagedWorkflowTools/verifyManagedNativeBoundaries.ts`,
//! `src/application/managed/ManagedNativeVerificationService.ts`,
//! `src/domain/managed/managedNativeVerification.ts` and
//! `managedNativeVerificationMatch.ts`.
use super::error::{DomainError, classify};
use super::inspection::{self, InspectionKind};
use super::unknown::{self, Probe, WorkflowUnknown};
use crate::common::json;
use rea_core::analysis_error::AnalysisError;
use rea_core::evidence::envelope::Observation;
use rea_mcp::{ToolContext, ToolOutput};
use serde_json::{Map, Value, json};

const OPERATION: &str = "verify_managed_native_boundaries";

pub fn handle(context: &ToolContext<'_>, input: Value) -> ToolOutput {
    let refinements = observation_refinements(&input);
    if !refinements.is_empty() {
        return crate::common::refinement_failure(OPERATION, refinements);
    }
    // `resolveManagedBoundaryEvidence(input.managed_boundaries)`.
    let managed_boundaries = match input.get("managed_boundaries") {
        Some(value) => value,
        None => {
            return ToolOutput::Failure(AnalysisError::evidence_integrity(
                "Managed boundary Evidence resolution failed",
            ));
        }
    };
    let managed_boundary = match super::resolve_expected(
        managed_boundaries,
        Some("inspect_managed_native_boundaries"),
    ) {
        Ok(record) => record,
        Err(error) => return ToolOutput::Failure(error),
    };
    // `resolveNativeEvidence(input.native_observations)`: authenticate each
    // record without an operation allowlist.
    let native_inputs = input
        .get("native_observations")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut native_observations: Vec<Value> = Vec::with_capacity(native_inputs.len());
    for value in &native_inputs {
        match super::resolve_expected(value, None) {
            Ok(record) => native_observations.push(record),
            Err(error) => return ToolOutput::Failure(error),
        }
    }
    // `verifyManagedNativeBoundariesEvidence(parsed)`.
    let derived = match verify(&managed_boundary, &native_observations) {
        Ok(derived) => derived,
        Err(error) => return ToolOutput::Failure(classify(OPERATION, error)),
    };
    // `recordSessionEvidenceSources([managed_boundaries, ...native_observations])`.
    let mut sources: Vec<&Value> = Vec::with_capacity(1 + native_observations.len());
    sources.push(&managed_boundary);
    sources.extend(native_observations.iter());
    if let Err(error) = super::record_sources(context.session, &sources) {
        return ToolOutput::Failure(error);
    }
    // Create the derived Evidence, then scope any residual unknown to its id.
    let normalized_result = derived.normalized_result.clone();
    let evidence = match crate::common::create_evidence(
        OPERATION,
        None,
        &crate::common::managed_workflow_provider(),
        derived.observation,
    ) {
        Ok(evidence) => evidence,
        Err(error) => return ToolOutput::Failure(error),
    };
    let unknown = match residual_unknown(evidence.id(), &normalized_result) {
        Ok(unknown) => unknown,
        Err(error) => return ToolOutput::Failure(error),
    };
    super::deliver(context.session, evidence, unknown)
}

struct DerivedEvidence {
    normalized_result: Value,
    observation: Observation,
}

/// `verifyManagedNativeBoundariesEvidence` + `verifyManagedNativeBoundaries` +
/// `createManagedNativeVerificationEvidence`.
fn verify(
    managed_boundary: &Value,
    native_observations: &[Value],
) -> Result<DerivedEvidence, DomainError> {
    // `parseManagedBoundary`.
    let parsed = inspection::parse(
        managed_boundary,
        "inspect_managed_native_boundaries",
        InspectionKind::Boundary,
    )?;
    let managed = &parsed.result;
    // `collectNativeSymbols`.
    let native = collect_native_symbols(native_observations)?;
    // `verifyPinvoke` for each declared import.
    let pinvoke_items = json::array_at(managed, "pinvoke_imports");
    let mut pinvoke_imports: Vec<Value> = Vec::with_capacity(pinvoke_items.len());
    for item in pinvoke_items {
        pinvoke_imports.push(verify_pinvoke(item, &parsed.evidence_id, &native)?);
    }
    // Native observation ids, in input order, for the top-level evidence links.
    let native_ids: Vec<String> = native_observations
        .iter()
        .map(|observation| {
            observation
                .get("evidence_id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned()
        })
        .collect();
    // `buildVerificationResult` + `verification_id`.
    let without_id = build_verification_result(
        &parsed,
        managed,
        &native,
        &pinvoke_imports,
        native_observations.len(),
        &native_ids,
    );
    let verification_id = format!("mnv_{}", canonical_digest(&without_id)?);
    // `{ ...withoutId, verification_id }` parsed by the result schema, which
    // lists `verification_id` first; emit it first to match the schema order.
    let mut ordered = Map::new();
    ordered.insert("verification_id".into(), json!(verification_id));
    if let Some(object) = without_id.as_object() {
        for (key, value) in object {
            ordered.insert(key.clone(), value.clone());
        }
    }
    let result = Value::Object(ordered);
    Ok(build_evidence(&parsed, result, &native_ids))
}

/// `managedNativeVerificationInputSchema.superRefine`: native observations
/// must be distinct from the managed boundary and unique among themselves.
/// The advertised JSON Schema cannot express it, so the SDK input-validation
/// failure is reproduced before any Evidence resolution.
fn observation_refinements(input: &Value) -> Vec<crate::common::Refinement> {
    let managed_id = input
        .get("managed_boundaries")
        .and_then(|managed| managed.get("evidence_id"));
    let mut refinements = Vec::new();
    let mut seen: Vec<Option<&Value>> = Vec::new();
    for (index, observation) in json::array_at(input, "native_observations")
        .iter()
        .enumerate()
    {
        let id = observation.get("evidence_id");
        let path = || vec![json!("native_observations"), json!(index)];
        if id == managed_id {
            refinements.push(crate::common::Refinement::new(
                path(),
                "Native observation Evidence must be distinct from managed boundary Evidence",
            ));
        }
        if seen.contains(&id) {
            refinements.push(crate::common::Refinement::new(
                path(),
                "Native observation Evidence IDs must be unique",
            ));
        }
        seen.push(id);
    }
    refinements
}

/// `sha256(canonicalize(value))`.
fn canonical_digest(value: &Value) -> Result<String, DomainError> {
    rea_core::canonical_json::digest(value)
        .map_err(|_| DomainError::type_error("Managed/native verification canonicalization failed"))
}

struct NativeSymbols {
    symbols: Vec<Value>,
    accepted: usize,
    unsupported: usize,
}

/// `collectNativeSymbols`.
fn collect_native_symbols(observations: &[Value]) -> Result<NativeSymbols, DomainError> {
    let mut symbols: Vec<Value> = Vec::new();
    let mut accepted = 0usize;
    let mut unsupported = 0usize;
    for evidence in observations {
        let (supported, extracted) = symbols_for_evidence(evidence);
        if !supported {
            unsupported += 1;
        } else {
            accepted += 1;
            symbols.extend(extracted);
        }
    }
    Ok(NativeSymbols {
        symbols,
        accepted,
        unsupported,
    })
}

/// `moduleName`: `evidence.subject?.name ?? null`.
fn module_name(evidence: &Value) -> Value {
    evidence
        .get("subject")
        .and_then(|subject| subject.get("name"))
        .cloned()
        .unwrap_or(Value::Null)
}

/// `modulePath`: `evidence.subject?.local_path ?? null`.
fn module_path(evidence: &Value) -> Value {
    evidence
        .get("subject")
        .and_then(|subject| subject.get("local_path"))
        .cloned()
        .unwrap_or(Value::Null)
}

/// `symbolsForEvidence`.
fn symbols_for_evidence(evidence: &Value) -> (bool, Vec<Value>) {
    let operation = evidence
        .get("operation")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let evidence_id = evidence
        .get("evidence_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let normalized = evidence
        .get("normalized_result")
        .cloned()
        .unwrap_or(Value::Null);
    if operation == "inspect_macho" {
        let items = normalized
            .get("exports")
            .and_then(|exports| exports.get("items"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let symbols = items
            .iter()
            .map(|symbol| {
                native_symbol(
                    evidence_id,
                    operation,
                    symbol.get("name").cloned().unwrap_or(Value::Null),
                    symbol.get("address").cloned().unwrap_or(Value::Null),
                    evidence,
                    "macho-export",
                )
            })
            .collect();
        return (true, symbols);
    }
    if operation == "analyze_function" {
        let procedure = normalized.get("procedure");
        let symbol = native_symbol(
            evidence_id,
            operation,
            procedure
                .and_then(|procedure| procedure.get("name"))
                .cloned()
                .unwrap_or(Value::Null),
            procedure
                .and_then(|procedure| procedure.get("address"))
                .cloned()
                .unwrap_or(Value::Null),
            evidence,
            "function-dossier",
        );
        return (true, vec![symbol]);
    }
    (false, Vec::new())
}

/// One `NativeSymbol` in schema key order.
fn native_symbol(
    evidence_id: &str,
    operation: &str,
    name: Value,
    address: Value,
    evidence: &Value,
    source: &str,
) -> Value {
    json!({
        "evidence_id": evidence_id,
        "operation": operation,
        "name": name,
        "address": address,
        "module_name": module_name(evidence),
        "module_path": module_path(evidence),
        "source": source,
    })
}

/// `normalizedSymbolName`: strip a single leading underscore from Mach-O
/// exports.
fn normalized_symbol_name(native: &Value) -> String {
    let name = native
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let source = native
        .get("source")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if source == "macho-export"
        && let Some(stripped) = name.strip_prefix('_')
    {
        return stripped.to_owned();
    }
    name.to_owned()
}

/// `sameSymbolName`.
fn same_symbol_name(expected: &str, native: &Value) -> bool {
    expected == normalized_symbol_name(native)
}

/// `basename`: last path segment for `/` and `\\` separators.
fn basename(value: &str) -> &str {
    let after_slash = value.rsplit('/').next().unwrap_or(value);
    after_slash.rsplit('\\').next().unwrap_or(after_slash)
}

/// `normalizeModule`: basename, lowercased, with a known shared-object
/// extension removed.
fn normalize_module(value: &str) -> String {
    let lowered = basename(value).to_lowercase();
    for extension in [".dll", ".dylib", ".so", ".node", ".exe"] {
        if let Some(stem) = lowered.strip_suffix(extension) {
            return stem.to_owned();
        }
    }
    lowered
}

/// `nativeModuleIdentities`.
fn native_module_identities(value: &str) -> Vec<String> {
    let filename = basename(value).to_lowercase();
    let stem = normalize_module(&filename);
    let mut identities = vec![stem.clone()];
    if (filename.ends_with(".dylib") || filename.ends_with(".so"))
        && let Some(trimmed) = stem.strip_prefix("lib")
    {
        identities.push(trimmed.to_owned());
    }
    identities
}

/// `moduleCompatible`.
fn module_compatible(scope: Option<&str>, symbol: &Value) -> bool {
    let Some(scope) = scope else { return false };
    if scope.trim().is_empty() {
        return false;
    }
    let expected = normalize_module(scope);
    for key in ["module_name", "module_path"] {
        if let Some(value) = symbol.get(key).and_then(Value::as_str)
            && !normalize_module(value).is_empty()
            && native_module_identities(value)
                .iter()
                .any(|identity| identity == &expected)
        {
            return true;
        }
    }
    false
}

/// `hasModuleIdentity`.
fn has_module_identity(symbol: &Value) -> bool {
    for key in ["module_name", "module_path"] {
        if let Some(value) = symbol.get(key).and_then(Value::as_str)
            && !normalize_module(value).is_empty()
        {
            return true;
        }
    }
    false
}

/// `candidateNames`: declared import plus mangled aliases unless `no_mangle`.
fn candidate_names(managed: &Value) -> Vec<String> {
    let import_name = managed
        .get("import_name")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let no_mangle = managed
        .get("no_mangle")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let char_set = managed
        .get("char_set")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let call_convention = managed
        .get("call_convention")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let mut names: Vec<String> = vec![import_name.clone()];
    fn push_unique(names: &mut Vec<String>, value: String) {
        if !names.contains(&value) {
            names.push(value);
        }
    }
    if !no_mangle {
        if char_set == "unicode" {
            push_unique(&mut names, format!("{import_name}W"));
        }
        if char_set == "ansi" {
            push_unique(&mut names, format!("{import_name}A"));
        }
        if call_convention == "stdcall" {
            push_unique(&mut names, format!("_{import_name}"));
            push_unique(&mut names, format!("_{import_name}@0"));
        }
    }
    names
}

/// `matchPinvoke`'s selected match.
struct PinvokeMatch {
    status: &'static str,
    basis: &'static str,
    confidence: &'static str,
    matched_native: Value,
    candidates: Vec<Value>,
}

/// `matchPinvoke`.
fn match_pinvoke(managed: &Value, symbols: &[Value], supported_native: usize) -> PinvokeMatch {
    let names = candidate_names(managed);
    let all_candidates: Vec<Value> = symbols
        .iter()
        .filter(|symbol| names.iter().any(|name| same_symbol_name(name, symbol)))
        .cloned()
        .collect();
    let Some(first) = all_candidates.first().cloned() else {
        return PinvokeMatch {
            status: "unresolved",
            basis: if supported_native > 0 {
                "no-native-candidate"
            } else {
                "unsupported-native-evidence"
            },
            confidence: "unknown",
            matched_native: Value::Null,
            candidates: Vec::new(),
        };
    };
    let candidates = all_candidates;
    let import_name = managed
        .get("import_name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let import_scope = managed.get("import_scope_name").and_then(Value::as_str);
    let scope_known = import_scope
        .map(|scope| !scope.trim().is_empty())
        .unwrap_or(false);
    let exact_index = candidates.iter().position(|symbol| {
        import_name == normalized_symbol_name(symbol) && module_compatible(import_scope, symbol)
    });
    let decorated_index = candidates
        .iter()
        .position(|symbol| module_compatible(import_scope, symbol));
    let selected = exact_index
        .or(decorated_index)
        .or_else(|| {
            if scope_known {
                candidates
                    .iter()
                    .position(|symbol| !has_module_identity(symbol))
            } else {
                None
            }
        })
        .map(|index| candidates[index].clone())
        .unwrap_or_else(|| first.clone());
    if exact_index.is_some() {
        let basis = if selected.get("source").and_then(Value::as_str) == Some("macho-export") {
            "exact-export-name"
        } else {
            "exact-function-name"
        };
        return PinvokeMatch {
            status: "verified",
            basis,
            confidence: "observed",
            matched_native: selected,
            candidates,
        };
    }
    if decorated_index.is_some() {
        return PinvokeMatch {
            status: "inferred",
            basis: "decorated-name-candidate",
            confidence: "inferred",
            matched_native: selected,
            candidates,
        };
    }
    if !scope_known || !has_module_identity(&selected) {
        return PinvokeMatch {
            status: "unresolved",
            basis: "module-identity-unknown",
            confidence: "unknown",
            matched_native: selected,
            candidates,
        };
    }
    PinvokeMatch {
        status: "contradicted",
        basis: "module-mismatch",
        confidence: "unknown",
        matched_native: selected,
        candidates,
    }
}

/// `pinvokeLimitations`.
fn pinvoke_limitations(match_result: &PinvokeMatch, managed: &Value) -> Vec<String> {
    let mut limitations: Vec<String> = Vec::new();
    let scope = managed.get("import_scope_name").and_then(Value::as_str);
    if scope.map(|scope| scope.trim().is_empty()).unwrap_or(true) {
        limitations.push("Managed declaration does not name an import scope/module.".to_owned());
    }
    if match_result.status == "inferred" {
        limitations.push(
            "Native symbol matched a decorated candidate rather than the exact declared import name."
                .to_owned(),
        );
    }
    if match_result.status == "contradicted" {
        limitations.push(
            "A symbol name candidate exists, but the supplied native Evidence module identity does not match the managed import scope."
                .to_owned(),
        );
    }
    if match_result.status == "unresolved" {
        if match_result.basis == "module-identity-unknown" {
            limitations.push(
                "A native name candidate exists, but a required module identity is unavailable; module correspondence is unknown."
                    .to_owned(),
            );
        } else {
            limitations.push(
                "No supplied native export/function Evidence matched this declared import."
                    .to_owned(),
            );
        }
    }
    limitations
}

/// `verifyPinvoke`: one `PinvokeVerification` in schema key order.
fn verify_pinvoke(
    item: &Value,
    managed_evidence_id: &str,
    native: &NativeSymbols,
) -> Result<Value, DomainError> {
    let managed = json!({
        "token": item.get("token").cloned().unwrap_or(Value::Null),
        "member_token": item.get("member_token").cloned().unwrap_or(Value::Null),
        "member_name": item.get("member_name").cloned().unwrap_or(Value::Null),
        "import_name": item.get("import_name").cloned().unwrap_or(Value::Null),
        "import_scope_name": item.get("import_scope_name").cloned().unwrap_or(Value::Null),
        "no_mangle": item.get("no_mangle").cloned().unwrap_or(Value::Null),
        "char_set": item.get("char_set").cloned().unwrap_or(Value::Null),
        "call_convention": item.get("call_convention").cloned().unwrap_or(Value::Null),
        "declaration_verification": item.get("verification").cloned().unwrap_or(Value::Null),
    });
    let selection = match_pinvoke(item, &native.symbols, native.accepted);
    let limitations = pinvoke_limitations(&selection, item);
    // `item_id = mnv_pinvoke_${digest({ managedEvidenceId, token, importName,
    // importScope, candidates })}`.
    let digest_input = json!({
        "managedEvidenceId": managed_evidence_id,
        "token": item.get("token").cloned().unwrap_or(Value::Null),
        "importName": item.get("import_name").cloned().unwrap_or(Value::Null),
        "importScope": item.get("import_scope_name").cloned().unwrap_or(Value::Null),
        "candidates": Value::Array(selection.candidates.clone()),
    });
    let item_id = format!("mnv_pinvoke_{}", canonical_digest(&digest_input)?);
    // `evidence_links = [managedEvidenceId, ...unique candidate evidence ids]`.
    let mut evidence_links: Vec<Value> = vec![json!(managed_evidence_id)];
    let mut seen: Vec<String> = Vec::new();
    for candidate in &selection.candidates {
        if let Some(id) = candidate.get("evidence_id").and_then(Value::as_str)
            && !seen.iter().any(|existing| existing == id)
        {
            seen.push(id.to_owned());
            evidence_links.push(json!(id));
        }
    }
    // Schema key order: item_id, managed, status, basis, confidence,
    // matched_native, candidates, evidence_links, limitations.
    let mut object = Map::new();
    object.insert("item_id".into(), json!(item_id));
    object.insert("managed".into(), managed);
    object.insert("status".into(), json!(selection.status));
    object.insert("basis".into(), json!(selection.basis));
    object.insert("confidence".into(), json!(selection.confidence));
    object.insert("matched_native".into(), selection.matched_native.clone());
    object.insert(
        "candidates".into(),
        Value::Array(selection.candidates.clone()),
    );
    object.insert("evidence_links".into(), Value::Array(evidence_links));
    object.insert(
        "limitations".into(),
        Value::Array(limitations.into_iter().map(Value::String).collect()),
    );
    Ok(Value::Object(object))
}

const VERIFICATION_REASON: &str = "Managed metadata tokens and RVAs are not translated to native provider addresses by this workflow; C++/CLI, ReadyToRun, and native-body mappings require explicit provider-supported bridge evidence.";

/// `buildVerificationResult`: everything but `verification_id`, in key order.
fn build_verification_result(
    parsed: &inspection::ParsedInspection,
    managed: &Value,
    native: &NativeSymbols,
    pinvoke_imports: &[Value],
    native_observations_total: usize,
    native_ids: &[String],
) -> Value {
    let counts = count_statuses(pinvoke_imports);
    let native_implementations = json::array_at(managed, "native_implementations");
    let native_body_unresolved = native_implementations
        .iter()
        .filter(|item| item.get("boundary_kind").and_then(Value::as_str) != Some("pinvoke"))
        .count();
    let coverage_state = managed
        .get("coverage")
        .and_then(|coverage| coverage.get("state"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let coverage_status = if coverage_state == "complete" && native.unsupported == 0 {
        "complete-within-inputs"
    } else {
        "partial"
    };
    let pinvoke_total = json::array_at(managed, "pinvoke_imports").len();
    let implementations_total = native_implementations.len();
    let mut limitations: Vec<String> = vec![
        "P/Invoke verification checks declared import names against supplied native export or function-name Evidence only.".to_owned(),
        "A matching native symbol verifies that a candidate export/function was observed; it does not prove CLR binding, marshaling behavior, call reachability, or runtime loading.".to_owned(),
        "Missing supplied native symbols are reported as unresolved, not proof that a dependency cannot exist.".to_owned(),
        "Managed metadata tokens and method RVAs are not interpreted as native addresses.".to_owned(),
    ];
    if coverage_state != "complete" {
        limitations.push("Managed boundary input is partial or unavailable.".to_owned());
    }
    if native.unsupported != 0 {
        limitations
            .push("Some native Evidence operations were unsupported by this workflow.".to_owned());
    }
    let artifact_sha256 = artifact_field(managed, "sha256");
    let artifact_path = artifact_field(managed, "path");
    let module_mvid = managed
        .get("module")
        .and_then(|module| module.get("mvid"))
        .cloned()
        .unwrap_or(Value::Null);
    let metadata_status = managed
        .get("metadata")
        .and_then(|metadata| metadata.get("status"))
        .cloned()
        .unwrap_or(Value::Null);
    // `evidence_links = [managedEvidenceId, ...native observation ids]`.
    let mut evidence_links: Vec<Value> = vec![json!(parsed.evidence_id.clone())];
    for id in native_ids {
        evidence_links.push(json!(id));
    }
    json!({
        "algorithm": {
            "name": "rea-managed-native-verification",
            "token_identity": "build-local",
            "token_to_address_mapping": "not-inferred",
        },
        "managed_boundary": {
            "evidence_id": parsed.evidence_id.clone(),
            "artifact_sha256": artifact_sha256,
            "artifact_path": artifact_path,
            "mvid": module_mvid,
            "metadata_status": metadata_status,
            "pinvoke_imports_total": pinvoke_total,
            "native_implementations_total": implementations_total,
            "coverage_state": coverage_state,
        },
        "native_observations": {
            "total": native_observations_total,
            "accepted": native.accepted,
            "unsupported": native.unsupported,
            "symbols": native.symbols.len(),
        },
        "summary": {
            "verified": counts.0,
            "inferred": counts.1,
            "unresolved": counts.2,
            "contradicted": counts.3,
            "native_body_unresolved": native_body_unresolved,
        },
        "pinvoke_imports": Value::Array(pinvoke_imports.to_vec()),
        "native_implementations": {
            "unresolved": native_body_unresolved,
            "reason": VERIFICATION_REASON,
        },
        "coverage": { "status": coverage_status },
        "evidence_links": Value::Array(evidence_links),
        "limitations": Value::Array(limitations.into_iter().map(Value::String).collect()),
    })
}

/// `countStatuses` → (verified, inferred, unresolved, contradicted).
fn count_statuses(items: &[Value]) -> (usize, usize, usize, usize) {
    let count = |status: &str| {
        items
            .iter()
            .filter(|item| item.get("status").and_then(Value::as_str) == Some(status))
            .count()
    };
    (
        count("verified"),
        count("inferred"),
        count("unresolved"),
        count("contradicted"),
    )
}

fn artifact_field(managed: &Value, key: &str) -> Value {
    managed
        .get("artifact")
        .and_then(|artifact| artifact.get(key))
        .cloned()
        .unwrap_or(Value::Null)
}

/// `createManagedNativeVerificationEvidence`.
fn build_evidence(
    parsed: &inspection::ParsedInspection,
    result: Value,
    native_ids: &[String],
) -> DerivedEvidence {
    let parameters = json!({
        "managed_boundaries_evidence_id": parsed.evidence_id.clone(),
        "native_evidence_ids": Value::Array(native_ids.iter().map(|id| json!(id)).collect()),
    });
    let limitations = json::strings(result.get("limitations").unwrap_or(&Value::Null));
    let evidence_links = json::strings(result.get("evidence_links").unwrap_or(&Value::Null));
    let observation = Observation::new(OPERATION, parameters, result.clone())
        .predicate("rea.managed-native-verification")
        .confidence("inferred")
        .authority("analyst-inference")
        .environment(Value::Null)
        .limitations(limitations)
        .links(evidence_links);
    DerivedEvidence {
        normalized_result: result,
        observation,
    }
}

/// `workflowUnknownInput(result.evidence_id, {...})` when the summary reports
/// unresolved, contradicted, or native-body-unresolved boundaries.
fn residual_unknown(
    evidence_id: &str,
    normalized_result: &Value,
) -> Result<Option<Value>, AnalysisError> {
    let summary = normalized_result
        .get("summary")
        .cloned()
        .unwrap_or(Value::Null);
    let field = |key: &str| summary.get(key).and_then(Value::as_u64).unwrap_or(0);
    let unknown =
        field("unresolved") > 0 || field("contradicted") > 0 || field("native_body_unresolved") > 0;
    if !unknown {
        return Ok(None);
    }
    let input = unknown::workflow_unknown_input(
        evidence_id,
        WorkflowUnknown {
            question: "Which managed/native boundaries remain unresolved or contradicted by the supplied native Evidence?",
            severity: "medium",
            domain: "managed-native-verification",
            required_authority: "shipped-artifact",
            required_confidence: "observed",
            recommended_probes: vec![
                Probe {
                    operation: "inspect_managed_native_boundaries",
                    rationale: "Review the inspection Evidence coverage and limit diagnostics; this operation has no page override, so unresolved declarations must remain unknown.",
                },
                Probe {
                    operation: "analyze_function",
                    rationale: "Analyze the provider-resolved native function candidate for the declared export.",
                },
            ],
        },
    )?;
    Ok(Some(input))
}
