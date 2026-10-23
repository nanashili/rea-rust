//! Inline fail-closed reconstruction coverage evaluation.
//!
//! Compatibility owners: `src/server/registerApplicationTools/coverage.ts`,
//! `src/application/ReconstructionCoverageService.ts`,
//! `src/domain/reconstructionCoverage.ts`,
//! `src/domain/reconstructionCoverageEvaluation.ts`,
//! `src/domain/reconstructionCoverageEvidence.ts`,
//! `src/domain/reconstructionCoverageVerifierResults.ts` and
//! `src/domain/offsetDateTime.ts`.
use crate::bundle;
use crate::rejection::Rejection;
use crate::sdk_input::{Trimmer, extend};
use rea_core::analysis_error::AnalysisError;
use rea_core::canonical_json;
use rea_mcp::{Registry, ToolOutput};
use serde_json::{Value, json};
use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

pub const OPERATION: &str = "evaluate_reconstruction_coverage";
const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

pub fn register(registry: &mut Registry) {
    registry.handle(OPERATION, |context, mut input| {
        if let Some(failure) = trim_request(&mut input["coverage"]).failure(context.contract) {
            return ToolOutput::Raw(failure);
        }
        match evaluate_reconstruction_coverage(&input, now_epoch_ms()) {
            Ok(result) => ToolOutput::Value(result),
            Err(error) => ToolOutput::Failure(error),
        }
    });
}

fn now_epoch_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}

/// `evaluateReconstructionCoverage(rawInput, nowEpochMs)` after request parsing.
pub fn evaluate_reconstruction_coverage(
    input: &Value,
    now_epoch_ms: i64,
) -> Result<Value, AnalysisError> {
    let boundary_id = input["boundary_id"].as_str().unwrap_or_default();
    evaluate_closure(&input["coverage"], boundary_id, now_epoch_ms)
        .map_err(|rejection| rejection.into_input_error(OPERATION))
}

/// Apply the request schema's trimmed text fields in Zod traversal order.
fn trim_request(coverage: &mut Value) -> Trimmer {
    let mut trimmer = Trimmer::default();
    let root = vec!["coverage".to_owned()];
    let mut trim = |collection: &str, fields: &dyn Fn(&Value) -> Vec<&'static [&'static str]>| {
        let Some(items) = coverage[collection].as_array_mut() else {
            return;
        };
        for (index, item) in items.iter_mut().enumerate() {
            for field in fields(item) {
                let mut target = &mut *item;
                for part in field {
                    target = &mut target[*part];
                }
                let mut path = extend(&root, &[collection, &index.to_string()]);
                path.extend(field.iter().map(|part| (*part).to_owned()));
                trimmer.field(target, &path);
            }
        }
    };
    trim("artifacts", &|_| vec![&["version"]]);
    trim("surfaces", &|_| {
        vec![&["family"], &["occurrence_id"], &["location"]]
    });
    trim("owners", &|owner| {
        if owner["ownership"]["disposition"] == "implemented" {
            vec![&["ownership", "owner_path"], &["ownership", "owner_export"]]
        } else {
            vec![&["ownership", "rationale"]]
        }
    });
    trim("claims", &|_| vec![&["title"], &["kind"]]);
    trim("boundaries", &|_| vec![&["title"]]);
    trimmer
}

/// Validated lookup facts of `parseCoverageData`.
struct Parsed<'a> {
    coverage: &'a Value,
    evidence_by_id: HashMap<String, Value>,
    artifacts: HashMap<String, &'a Value>,
    surfaces: HashMap<String, &'a Value>,
    claims: HashMap<String, &'a Value>,
    owners_by_surface: HashMap<String, Vec<&'a Value>>,
}

/// `evaluateReconstructionClosure(coverage, boundaryId, nowEpochMs)`.
fn evaluate_closure(
    coverage: &Value,
    boundary_id: &str,
    now_epoch_ms: i64,
) -> Result<Value, Rejection> {
    let parsed = validate_references(coverage)?;
    let Some(boundary) = items(coverage, "boundaries")
        .iter()
        .find(|boundary| boundary["boundary_id"].as_str() == Some(boundary_id))
    else {
        return Err(Rejection::type_error(format!(
            "Unknown reconstruction boundary: {boundary_id}"
        )));
    };
    let mut context = Context {
        parsed: &parsed,
        boundary,
        now_epoch_ms,
        now_instant: Instant::from_epoch_ms(now_epoch_ms),
        reasons: Vec::new(),
        evidence_ids: BTreeSet::new(),
    };
    context.evaluate_surfaces();
    context.evaluate_claims()?;
    context.evaluate_risks();
    context.evaluate_package_proofs();
    let mut reasons = context.reasons;
    reasons.sort_by(|left, right| reason_key(left).cmp(&reason_key(right)));
    let status = closure_status(&reasons);
    let probes: Vec<Value> = reasons
        .iter()
        .map(|reason| {
            json!({
                "operation": probe_operation(reason["code"].as_str().unwrap_or_default()),
                "subject_id": reason["subject_id"],
                "rationale": reason["detail"],
            })
        })
        .collect();
    Ok(json!({
        "boundary_id": boundary["boundary_id"],
        "status": status,
        "summary": {
            "required_surfaces": strings(boundary, "required_surface_ids").len(),
            "required_claims": strings(boundary, "required_claim_ids").len(),
            "reasons": reasons.len(),
        },
        "reasons": reasons,
        "recommended_probes": probes,
        "evidence_ids": context.evidence_ids.into_iter().collect::<Vec<_>>(),
    }))
}

fn reason_key(reason: &Value) -> String {
    serde_json::to_string(&json!([reason["code"], reason["subject_id"]])).unwrap_or_default()
}

/// `validateCoverageReferences`.
fn validate_references(coverage: &Value) -> Result<Parsed<'_>, Rejection> {
    let authenticated = bundle::authenticate(&coverage["evidence_bundle"])?;
    let artifacts = index_unique(coverage, "artifacts", "artifact_id")?;
    let surfaces = index_unique(coverage, "surfaces", "surface_id")?;
    let claims = index_unique(coverage, "claims", "claim_id")?;
    let contracts = index_unique(coverage, "verifier_contracts", "verifier_id")?;
    index_unique(coverage, "contradictions", "contradiction_id")?;
    index_unique(coverage, "package_proofs", "proof_id")?;
    index_unique(coverage, "boundaries", "boundary_id")?;
    for contract in items(coverage, "verifier_contracts") {
        let mut base = contract.as_object().cloned().unwrap_or_default();
        let declared = base.remove("contract_sha256");
        let expected = canonical_json::digest(&Value::Object(base)).map_err(|_| {
            Rejection::type_error("Reconstruction coverage value is not canonical JSON")
        })?;
        if declared.as_ref().and_then(Value::as_str) != Some(expected.as_str()) {
            return Err(Rejection::type_error(format!(
                "Verifier contract digest is invalid: {}",
                text(&contract["verifier_id"])
            )));
        }
    }
    for surface in items(coverage, "surfaces") {
        if !artifacts.contains_key(text(&surface["artifact_id"])) {
            return Err(Rejection::type_error(format!(
                "Surface artifact is missing: {}",
                text(&surface["surface_id"])
            )));
        }
    }
    let mut owners_by_surface: HashMap<String, Vec<&Value>> = HashMap::new();
    for owner in items(coverage, "owners") {
        let surface_id = text(&owner["surface_id"]);
        if !surfaces.contains_key(surface_id) {
            return Err(Rejection::type_error(format!(
                "Owner surface is missing: {surface_id}"
            )));
        }
        owners_by_surface
            .entry(surface_id.to_owned())
            .or_default()
            .push(owner);
    }
    for claim in items(coverage, "claims") {
        if strings(claim, "surface_ids")
            .iter()
            .any(|id| !surfaces.contains_key(*id))
        {
            return Err(Rejection::type_error(format!(
                "Claim surface is missing: {}",
                text(&claim["claim_id"])
            )));
        }
    }
    for contract in items(coverage, "verifier_contracts") {
        if strings(contract, "claim_ids")
            .iter()
            .any(|id| !claims.contains_key(*id))
        {
            return Err(Rejection::type_error(format!(
                "Verifier claim is missing: {}",
                text(&contract["verifier_id"])
            )));
        }
    }
    for result in items(coverage, "verifier_results") {
        if !contracts.contains_key(text(&result["verifier_id"])) {
            return Err(Rejection::type_error(format!(
                "Verifier result contract is missing: {}",
                text(&result["verifier_id"])
            )));
        }
    }
    let referenced = [
        "artifacts",
        "surfaces",
        "verifier_results",
        "contradictions",
        "package_proofs",
    ]
    .iter()
    .flat_map(|collection| items(coverage, collection))
    .flat_map(|item| strings(item, "evidence_ids"));
    for id in referenced {
        if !authenticated.by_id.contains_key(id) {
            return Err(Rejection::type_error(format!(
                "Coverage workspace Evidence is missing: {id}"
            )));
        }
    }
    for id in strings(coverage, "residual_unknown_ids") {
        if !authenticated.unknown_ids.contains(id) {
            return Err(Rejection::type_error(format!(
                "Coverage workspace residual unknown is missing: {id}"
            )));
        }
    }
    Ok(Parsed {
        coverage,
        evidence_by_id: authenticated.by_id,
        artifacts,
        surfaces,
        claims,
        owners_by_surface,
    })
}

fn index_unique<'a>(
    coverage: &'a Value,
    collection: &str,
    key: &str,
) -> Result<HashMap<String, &'a Value>, Rejection> {
    let mut values = HashMap::new();
    for item in items(coverage, collection) {
        if values.insert(text(&item[key]).to_owned(), item).is_some() {
            return Err(Rejection::type_error(format!(
                "Duplicate reconstruction coverage {key}"
            )));
        }
    }
    Ok(values)
}

struct Context<'a> {
    parsed: &'a Parsed<'a>,
    boundary: &'a Value,
    now_epoch_ms: i64,
    now_instant: Instant,
    reasons: Vec<Value>,
    evidence_ids: BTreeSet<String>,
}

impl Context<'_> {
    fn add_reason(&mut self, code: &str, subject_id: &str, detail: impl Into<String>) {
        self.reasons.push(json!({
            "code": code,
            "subject_id": subject_id,
            "detail": detail.into(),
        }));
    }

    fn add_evidence<'v>(&mut self, ids: impl IntoIterator<Item = &'v str>) {
        self.evidence_ids.extend(ids.into_iter().map(str::to_owned));
    }

    fn evaluate_surfaces(&mut self) {
        for surface_id in strings(self.boundary, "required_surface_ids") {
            let Some(surface) = self.parsed.surfaces.get(surface_id).copied() else {
                self.add_reason(
                    "surface-missing",
                    surface_id,
                    "Required surface is absent from the authoritative inventory.",
                );
                continue;
            };
            self.add_evidence(strings(surface, "evidence_ids"));
            for dependency in strings(surface, "dependency_surface_ids") {
                if !self.parsed.surfaces.contains_key(dependency) {
                    self.add_reason(
                        "dependency-surface-missing",
                        surface_id,
                        format!("Declared dependency surface is absent: {dependency}"),
                    );
                }
            }
            self.evaluate_owner(surface_id);
        }
    }

    fn evaluate_owner(&mut self, surface_id: &str) {
        let owners = self
            .parsed
            .owners_by_surface
            .get(surface_id)
            .cloned()
            .unwrap_or_default();
        if owners.is_empty() {
            self.add_reason(
                "owner-missing",
                surface_id,
                "Required surface has no reconstructed owner or explicit disposition.",
            );
            return;
        }
        if owners.len() > 1 {
            self.add_reason(
                "owner-duplicate",
                surface_id,
                "Required surface has conflicting ownership declarations.",
            );
            return;
        }
        let owner = &owners[0]["ownership"];
        let disposition = text(&owner["disposition"]);
        if disposition != "implemented" {
            if !strings(self.boundary, "allowed_dispositions").contains(&disposition) {
                self.add_reason(
                    "disposition-not-allowed",
                    surface_id,
                    format!("{disposition} is not allowed by this completion boundary."),
                );
            }
            return;
        }
        let path_state = text(&owner["path_state"]);
        let package_state = text(&owner["package_state"]);
        let route = text(&owner["authority_route"]);
        let checks = [
            (
                path_state == "missing",
                "owner-path-missing",
                "Declared owner path is missing.",
            ),
            (
                path_state == "unknown",
                "owner-path-unknown",
                "Declared owner path has not been checked.",
            ),
            (
                package_state == "missing",
                "owner-undistributed",
                "Declared owner is absent from the distributable.",
            ),
            (
                package_state == "unknown",
                "owner-distribution-unknown",
                "Owner distribution state is unknown.",
            ),
            (
                route == "detected",
                "authority-routing-detected",
                "Reconstructed owner routes into the authority.",
            ),
            (
                route == "unknown",
                "authority-routing-unknown",
                "Authority independence has not been established.",
            ),
        ];
        for (matches, code, detail) in checks {
            if matches {
                self.add_reason(code, surface_id, detail);
            }
        }
    }

    fn evaluate_claims(&mut self) -> Result<(), Rejection> {
        let coverage = self.parsed.coverage;
        let mut contracts_by_claim: HashMap<&str, Vec<&Value>> = HashMap::new();
        for contract in items(coverage, "verifier_contracts") {
            let mut seen = HashSet::new();
            for claim_id in strings(contract, "claim_ids") {
                if seen.insert(claim_id) {
                    contracts_by_claim
                        .entry(claim_id)
                        .or_default()
                        .push(contract);
                }
            }
        }
        let latest = latest_observations(items(coverage, "verifier_results"))?;
        let artifact_digests: HashSet<&str> = items(coverage, "artifacts")
            .iter()
            .map(|artifact| text(&artifact["artifact_sha256"]))
            .collect();
        let owner_digests: HashSet<&str> = items(coverage, "owners")
            .iter()
            .filter(|owner| owner["ownership"]["disposition"] == "implemented")
            .map(|owner| text(&owner["ownership"]["owner_sha256"]))
            .collect();
        for claim_id in strings(self.boundary, "required_claim_ids") {
            let Some(claim) = self.parsed.claims.get(claim_id).copied() else {
                self.add_reason(
                    "claim-missing",
                    claim_id,
                    "Required finite claim is absent.",
                );
                continue;
            };
            let contracts = contracts_by_claim
                .get(claim_id)
                .cloned()
                .unwrap_or_default();
            if contracts.is_empty() {
                self.add_reason(
                    "verifier-missing",
                    claim_id,
                    "No verifier contract covers this claim.",
                );
                continue;
            }
            if contracts.len() > 1 {
                self.add_reason(
                    "verifier-duplicate",
                    claim_id,
                    "Multiple verifier contracts claim primary coverage.",
                );
                continue;
            }
            self.evaluate_verifier_result(
                claim,
                contracts[0],
                &latest,
                &artifact_digests,
                &owner_digests,
            );
        }
        Ok(())
    }

    fn evaluate_verifier_result(
        &mut self,
        claim: &Value,
        contract: &Value,
        latest: &HashMap<String, Vec<Observation<'_>>>,
        artifact_digests: &HashSet<&str>,
        owner_digests: &HashSet<&str>,
    ) {
        let claim_id = text(&claim["claim_id"]);
        let Some(results) = latest.get(text(&contract["verifier_id"])) else {
            self.add_reason(
                "verifier-result-missing",
                claim_id,
                "Verifier has no recorded result.",
            );
            return;
        };
        self.add_evidence(
            results
                .iter()
                .flat_map(|observation| strings(observation.result, "evidence_ids")),
        );
        let first = &results[0];
        let identity = assessment_identity(first.result);
        if !results
            .iter()
            .all(|candidate| assessment_identity(candidate.result) == identity)
        {
            self.add_reason(
                "verifier-result-ambiguous",
                claim_id,
                "Latest verifier observations have conflicting assessment content.",
            );
            return;
        }
        let authority = text(&contract["authority"]);
        let Some(comparable) = results.iter().find(|observation| {
            has_comparable_evidence(
                &strings(observation.result, "evidence_ids"),
                &[authority],
                &self.parsed.evidence_by_id,
            )
        }) else {
            self.add_reason(
                "verifier-result-incompatible",
                claim_id,
                format!(
                    "Latest verifier observation has no cited Evidence with comparable {authority} authority and confidence."
                ),
            );
            return;
        };
        let result = comparable.result;
        if !self.result_matches_contract(claim, contract, result, artifact_digests, owner_digests) {
            self.add_reason(
                "verifier-result-incompatible",
                claim_id,
                "Latest verifier result does not match current artifacts, owners, dimensions, authority, normalization, repeats, or contract.",
            );
            return;
        }
        let max_age = contract["max_age_ms"].as_f64().unwrap_or(0.0);
        let cutoff = self.now_epoch_ms as f64 - max_age;
        let future = comparable.instant.compare(&self.now_instant) == Ordering::Greater;
        let stale = cutoff >= -(MAX_SAFE_INTEGER as f64)
            && comparable
                .instant
                .compare(&Instant::from_epoch_ms(cutoff as i64))
                == Ordering::Less;
        if future || stale {
            self.add_reason(
                "verifier-result-stale",
                claim_id,
                "Latest compatible verifier result is stale.",
            );
            return;
        }
        let status = text(&result["status"]);
        if status == "fail" {
            self.add_reason(
                "verifier-failed",
                claim_id,
                "Latest compatible verifier result failed.",
            );
        } else if status != "pass" {
            self.add_reason(
                "verifier-unknown",
                claim_id,
                format!("Latest compatible verifier result is {status}."),
            );
        }
    }

    fn result_matches_contract(
        &self,
        claim: &Value,
        contract: &Value,
        result: &Value,
        artifact_digests: &HashSet<&str>,
        owner_digests: &HashSet<&str>,
    ) -> bool {
        let surface_ids = strings(claim, "surface_ids");
        let expected_artifacts: Vec<&str> = surface_ids
            .iter()
            .filter_map(|id| self.parsed.surfaces.get(*id))
            .filter_map(|surface| self.parsed.artifacts.get(text(&surface["artifact_id"])))
            .map(|artifact| text(&artifact["artifact_sha256"]))
            .collect();
        let expected_owners: Vec<&str> = surface_ids
            .iter()
            .flat_map(|id| {
                self.parsed
                    .owners_by_surface
                    .get(*id)
                    .cloned()
                    .unwrap_or_default()
            })
            .filter(|owner| owner["ownership"]["disposition"] == "implemented")
            .map(|owner| text(&owner["ownership"]["owner_sha256"]))
            .collect();
        let claim_ids = strings(contract, "claim_ids");
        let dimensions = strings(contract, "dimensions");
        let covered_claims = strings(result, "covered_claim_ids");
        let covered_dimensions = strings(result, "covered_dimensions");
        let required_dimensions = strings(claim, "required_dimensions");
        let result_artifacts = strings(result, "artifact_sha256s");
        let result_owners = strings(result, "owner_sha256s");
        result["contract_sha256"] == contract["contract_sha256"]
            && result["normalization_sha256"] == contract["normalization_sha256"]
            && covered_claims.contains(&text(&claim["claim_id"]))
            && covered_claims.iter().all(|item| claim_ids.contains(item))
            && required_dimensions
                .iter()
                .all(|item| dimensions.contains(item))
            && required_dimensions
                .iter()
                .all(|item| covered_dimensions.contains(item))
            && covered_dimensions
                .iter()
                .all(|item| dimensions.contains(item))
            && result_artifacts
                .iter()
                .all(|item| artifact_digests.contains(item))
            && expected_artifacts
                .iter()
                .all(|item| result_artifacts.contains(item))
            && result_owners
                .iter()
                .all(|item| owner_digests.contains(item))
            && expected_owners
                .iter()
                .all(|item| result_owners.contains(item))
            && result["repeats"].as_f64().unwrap_or(0.0)
                >= contract["minimum_repeats"].as_f64().unwrap_or(0.0)
            && claim["required_authority"] == contract["authority"]
    }

    fn evaluate_risks(&mut self) {
        let coverage = self.parsed.coverage;
        let allowed = strings(self.boundary, "allowed_unknown_ids");
        for unknown_id in strings(coverage, "residual_unknown_ids") {
            if !allowed.contains(&unknown_id) {
                self.add_reason(
                    "active-unknown",
                    unknown_id,
                    "Active residual unknown is not permitted by the completion boundary.",
                );
            }
        }
        let required_surfaces = strings(self.boundary, "required_surface_ids");
        let required_claims = strings(self.boundary, "required_claim_ids");
        for contradiction in items(coverage, "contradictions") {
            if contradiction["status"] == "active"
                && (strings(contradiction, "surface_ids")
                    .iter()
                    .any(|id| required_surfaces.contains(id))
                    || strings(contradiction, "claim_ids")
                        .iter()
                        .any(|id| required_claims.contains(id)))
            {
                self.add_evidence(strings(contradiction, "evidence_ids"));
                self.add_reason(
                    "active-contradiction",
                    text(&contradiction["contradiction_id"]),
                    "Active contradiction affects the completion boundary.",
                );
            }
        }
    }

    fn evaluate_package_proofs(&mut self) {
        let coverage = self.parsed.coverage;
        let required_digests: Vec<&str> = strings(self.boundary, "required_surface_ids")
            .iter()
            .filter_map(|id| self.parsed.surfaces.get(*id))
            .filter_map(|surface| self.parsed.artifacts.get(text(&surface["artifact_id"])))
            .map(|artifact| text(&artifact["artifact_sha256"]))
            .collect();
        for kind in strings(self.boundary, "required_package_proof_kinds") {
            let proofs: Vec<&Value> = items(coverage, "package_proofs")
                .iter()
                .filter(|proof| proof["kind"].as_str() == Some(kind))
                .collect();
            let applicable = |proof: &Value| {
                let digests = strings(proof, "artifact_sha256s");
                required_digests
                    .iter()
                    .all(|digest| digests.contains(digest))
                    && has_comparable_evidence(
                        &strings(proof, "evidence_ids"),
                        package_authorities(text(&proof["kind"])),
                        &self.parsed.evidence_by_id,
                    )
            };
            if let Some(passing) = proofs
                .iter()
                .find(|proof| proof["status"] == "pass" && applicable(proof))
            {
                self.add_evidence(strings(passing, "evidence_ids"));
                continue;
            }
            if let Some(failing) = proofs
                .iter()
                .find(|proof| proof["status"] == "fail" && applicable(proof))
            {
                self.add_evidence(strings(failing, "evidence_ids"));
                self.add_reason(
                    "package-proof-failed",
                    kind,
                    "Required package or integration proof failed.",
                );
            } else if !proofs.is_empty() {
                self.add_evidence(
                    proofs
                        .iter()
                        .flat_map(|proof| strings(proof, "evidence_ids")),
                );
                self.add_reason(
                    "package-proof-unknown",
                    kind,
                    "Required package or integration proof has no qualifying passing Evidence.",
                );
            } else {
                self.add_reason(
                    "package-proof-missing",
                    kind,
                    "Required package or integration proof is missing.",
                );
            }
        }
    }
}

fn package_authorities(kind: &str) -> &'static [&'static str] {
    match kind {
        "package-contents" | "authority-independence" => &["shipped-artifact", "live-observation"],
        _ => &["live-observation"],
    }
}

fn evidence_authorities(required: &str) -> &'static [&'static str] {
    match required {
        "shipped-artifact" => &["shipped-artifact"],
        "controlled-replay" => &["controlled-replay"],
        "live-observation" => &["controlled-replay", "external-service"],
        _ => &["external-service"],
    }
}

/// `hasComparableEvidence`.
fn has_comparable_evidence(
    ids: &[&str],
    requirements: &[&str],
    records: &HashMap<String, Value>,
) -> bool {
    ids.iter().any(|id| {
        let Some(evidence) = records.get(*id) else {
            return false;
        };
        let authority = text(&evidence["authority"]);
        let confidence = text(&evidence["confidence"]);
        requirements.iter().any(|required| {
            evidence_authorities(required).contains(&authority)
                && (confidence == "observed"
                    || (*required == "shipped-artifact" && confidence == "derived"))
        })
    })
}

struct Observation<'a> {
    result: &'a Value,
    instant: Instant,
}

/// `latestVerifierObservationsByVerifier`.
fn latest_observations(
    results: &[Value],
) -> Result<HashMap<String, Vec<Observation<'_>>>, Rejection> {
    let mut latest: HashMap<String, Vec<Observation<'_>>> = HashMap::new();
    for result in results {
        let observation = Observation {
            result,
            instant: Instant::parse(text(&result["observed_at"]))?,
        };
        let verifier = text(&result["verifier_id"]).to_owned();
        match latest.get_mut(&verifier) {
            None => {
                latest.insert(verifier, vec![observation]);
            }
            Some(group) => match observation.instant.compare(&group[0].instant) {
                Ordering::Greater => *group = vec![observation],
                Ordering::Equal => group.push(observation),
                Ordering::Less => {}
            },
        }
    }
    Ok(latest)
}

/// `verifierAssessmentIdentity`: assessment content without timestamp and provenance.
fn assessment_identity(result: &Value) -> Value {
    let unique = |field: &str| -> Vec<String> {
        strings(result, field)
            .into_iter()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    };
    json!({
        "verifier_id": result["verifier_id"],
        "contract_sha256": result["contract_sha256"],
        "status": result["status"],
        "covered_claim_ids": unique("covered_claim_ids"),
        "covered_dimensions": unique("covered_dimensions"),
        "artifact_sha256s": unique("artifact_sha256s"),
        "owner_sha256s": unique("owner_sha256s"),
        "normalization_sha256": result["normalization_sha256"],
        "repeats": result["repeats"].as_f64(),
    })
}

fn closure_status(reasons: &[Value]) -> &'static str {
    if reasons.is_empty() {
        return "ready";
    }
    let has = |codes: &[&str]| {
        reasons
            .iter()
            .any(|reason| codes.contains(&text(&reason["code"])))
    };
    if has(&[
        "verifier-failed",
        "active-contradiction",
        "authority-routing-detected",
        "owner-path-missing",
        "owner-undistributed",
        "package-proof-failed",
    ]) {
        return "failed";
    }
    if has(&[
        "verifier-result-stale",
        "verifier-result-incompatible",
        "verifier-result-ambiguous",
        "verifier-unknown",
        "active-unknown",
        "owner-path-unknown",
        "owner-distribution-unknown",
        "authority-routing-unknown",
        "package-proof-unknown",
    ]) {
        return "unknown";
    }
    "partial"
}

fn probe_operation(code: &str) -> &'static str {
    if code.starts_with("owner-") || code.starts_with("authority-routing") {
        "reconcile_reconstruction_owner"
    } else if code.starts_with("verifier-") {
        "run_reconstruction_verifier"
    } else if code.starts_with("package-proof") {
        "verify_reconstruction_package"
    } else if code == "active-contradiction" {
        "resolve_contradiction"
    } else if code == "active-unknown" {
        "probe_residual_unknown"
    } else {
        "update_authoritative_inventory"
    }
}

/// `OffsetDateTimeInstant`: whole epoch seconds and exact fraction digits.
#[derive(Clone, Debug)]
struct Instant {
    epoch_second: i64,
    fraction: String,
}

impl Instant {
    /// `parseOffsetDateTimeInstant` for a schema-validated timestamp.
    fn parse(value: &str) -> Result<Self, Rejection> {
        let invalid = || Rejection::type_error("Expected a validated offset date-time.");
        let (body, offset_minutes) = if let Some(body) = value.strip_suffix('Z') {
            (body, 0i64)
        } else {
            if value.len() < 6 || !value.is_char_boundary(value.len() - 6) {
                return Err(invalid());
            }
            let (body, offset) = value.split_at(value.len() - 6);
            let sign = match offset.as_bytes()[0] {
                b'+' => 1,
                b'-' => -1,
                _ => return Err(invalid()),
            };
            let hours: i64 = offset[1..3].parse().map_err(|_| invalid())?;
            let minutes: i64 = offset[4..6].parse().map_err(|_| invalid())?;
            (body, sign * (hours * 60 + minutes))
        };
        let (date_time, fraction) = match body.split_once('.') {
            Some((date_time, fraction)) => (date_time, fraction),
            None => (body, ""),
        };
        let (date, time) = date_time.split_once('T').ok_or_else(invalid)?;
        let mut date_parts = date.split('-');
        let year: i64 = date_parts
            .next()
            .ok_or_else(invalid)?
            .parse()
            .map_err(|_| invalid())?;
        let month: i64 = date_parts
            .next()
            .ok_or_else(invalid)?
            .parse()
            .map_err(|_| invalid())?;
        let day: i64 = date_parts
            .next()
            .ok_or_else(invalid)?
            .parse()
            .map_err(|_| invalid())?;
        let mut time_parts = time.split(':');
        let hour: i64 = time_parts
            .next()
            .ok_or_else(invalid)?
            .parse()
            .map_err(|_| invalid())?;
        let minute: i64 = time_parts
            .next()
            .ok_or_else(invalid)?
            .parse()
            .map_err(|_| invalid())?;
        let second: i64 = match time_parts.next() {
            Some(second) => second.parse().map_err(|_| invalid())?,
            None => 0,
        };
        let epoch_second =
            days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second
                - offset_minutes * 60;
        if (epoch_second * 1000).abs() > 8_640_000_000_000_000 {
            return Err(Rejection::type_error(
                "Offset date-time is outside the supported time range.",
            ));
        }
        Ok(Self {
            epoch_second,
            fraction: fraction.trim_end_matches('0').to_owned(),
        })
    }

    /// `offsetDateTimeInstantFromEpochMilliseconds` for an integer instant.
    fn from_epoch_ms(milliseconds: i64) -> Self {
        let epoch_second = milliseconds.div_euclid(1000);
        let remainder = milliseconds.rem_euclid(1000);
        let fraction = if remainder == 0 {
            String::new()
        } else {
            format!("{remainder:03}").trim_end_matches('0').to_owned()
        };
        Self {
            epoch_second,
            fraction,
        }
    }

    /// `compareOffsetDateTimeInstants`.
    fn compare(&self, other: &Self) -> Ordering {
        self.epoch_second.cmp(&other.epoch_second).then_with(|| {
            let left = self.fraction.as_bytes();
            let right = other.fraction.as_bytes();
            for index in 0..left.len().max(right.len()) {
                let a = left.get(index).copied().unwrap_or(b'0');
                let b = right.get(index).copied().unwrap_or(b'0');
                if a != b {
                    return a.cmp(&b);
                }
            }
            Ordering::Equal
        })
    }
}

/// Days since 1970-01-01 in the proleptic Gregorian calendar.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month_index = (month + 9) % 12;
    let day_of_year = (153 * month_index + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn items<'a>(value: &'a Value, field: &str) -> &'a [Value] {
    value[field]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
}

fn strings<'a>(value: &'a Value, field: &str) -> Vec<&'a str> {
    items(value, field)
        .iter()
        .filter_map(Value::as_str)
        .collect()
}

fn text(value: &Value) -> &str {
    value.as_str().unwrap_or_default()
}
