//! Contract boundary for evidence-backed reconstruction coverage evaluation.

use crate::reconstruction::coverage_input::{self, Timestamp, compare_timestamps};
use rea_core::{
    evidence::bundle::EvidenceBundle,
    failure::{Detail, Failure},
};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::time::{SystemTime, UNIX_EPOCH};

pub const OPERATION: &str = "evaluate_reconstruction_coverage";

pub fn validate_input(input: &Value) -> Result<(), Failure> {
    coverage_input::validate(input).map(|_| ())
}

/// Evaluate one authenticated reconstruction snapshot at the current system time.
pub fn evaluate(input: &Value) -> Result<Value, Failure> {
    let evidence_bundle = coverage_input::validate(input)?;
    let now = current_timestamp()?;
    Ok(evaluate_validated(input, &evidence_bundle, &now))
}

/// Evaluate one authenticated reconstruction snapshot at an explicit instant.
///
/// The TypeScript application service accepts its evaluation clock explicitly;
/// keeping this entry point beside the wall-clock path lets native callers and
/// conformance tests make the same freshness decision deterministically.
pub fn evaluate_at(input: &Value, now: &str) -> Result<Value, Failure> {
    let evidence_bundle = coverage_input::validate(input)?;
    let now = coverage_input::parse_timestamp(now).map_err(|_| invalid_evaluation_timestamp())?;
    Ok(evaluate_validated(input, &evidence_bundle, &now))
}

fn evaluate_validated(input: &Value, evidence_bundle: &EvidenceBundle, now: &Timestamp) -> Value {
    let coverage = input
        .get("coverage")
        .and_then(Value::as_object)
        .expect("validated coverage");
    let boundary_id = input
        .get("boundary_id")
        .and_then(Value::as_str)
        .expect("validated boundary id");
    let boundary = values(coverage, "boundaries")
        .into_iter()
        .find(|item| string(item, "boundary_id") == Some(boundary_id))
        .expect("input validation selects a declared boundary");

    let mut evaluation = Evaluation::new(boundary_id);
    evaluation.evaluate_surfaces(coverage, boundary);
    evaluation.evaluate_claims(coverage, evidence_bundle, boundary, now);
    evaluation.evaluate_risks(coverage, boundary);
    evaluation.evaluate_package_proofs(coverage, evidence_bundle, boundary);
    evaluation.finish(boundary)
}

struct Evaluation {
    boundary_id: String,
    reasons: Vec<Value>,
    evidence_ids: BTreeSet<String>,
}

impl Evaluation {
    fn new(boundary_id: &str) -> Self {
        Self {
            boundary_id: boundary_id.to_owned(),
            reasons: Vec::new(),
            evidence_ids: BTreeSet::new(),
        }
    }

    fn evaluate_surfaces(&mut self, coverage: &Map<String, Value>, boundary: &Value) {
        let surfaces = values(coverage, "surfaces");
        let required = strings(boundary, "required_surface_ids");
        for surface_id in required {
            let Some(surface) = surfaces
                .iter()
                .find(|item| string(item, "surface_id") == Some(&surface_id))
            else {
                self.reason(
                    "surface-missing",
                    &surface_id,
                    "Required surface is absent from the authoritative inventory.",
                );
                continue;
            };
            self.evidence(strings(surface, "evidence_ids"));
            self.evaluate_dependencies(&surfaces, surface, &surface_id);
            self.evaluate_owner(coverage, boundary, &surface_id);
        }
    }

    fn evaluate_dependencies(&mut self, surfaces: &[&Value], surface: &Value, surface_id: &str) {
        for dependency in strings(surface, "dependency_surface_ids") {
            if !surfaces
                .iter()
                .any(|candidate| string(candidate, "surface_id") == Some(&dependency))
            {
                self.reason(
                    "dependency-surface-missing",
                    surface_id,
                    &format!("Declared dependency surface is absent: {dependency}"),
                );
            }
        }
    }

    fn evaluate_owner(
        &mut self,
        coverage: &Map<String, Value>,
        boundary: &Value,
        surface_id: &str,
    ) {
        let owners: Vec<&Value> = values(coverage, "owners")
            .into_iter()
            .filter(|owner| string(owner, "surface_id") == Some(surface_id))
            .collect();
        if owners.is_empty() {
            self.reason(
                "owner-missing",
                surface_id,
                "Required surface has no reconstructed owner or explicit disposition.",
            );
            return;
        }
        if owners.len() > 1 {
            self.reason(
                "owner-duplicate",
                surface_id,
                "Required surface has conflicting ownership declarations.",
            );
            return;
        }
        let Some(owner) = owners[0].get("ownership") else {
            return;
        };
        let disposition = string(owner, "disposition").unwrap_or_default();
        if disposition != "implemented" {
            if !strings(boundary, "allowed_dispositions")
                .iter()
                .any(|item| item == disposition)
            {
                self.reason(
                    "disposition-not-allowed",
                    surface_id,
                    &format!("{disposition} is not allowed by this completion boundary."),
                );
            }
            return;
        }
        self.owner_state(owner, surface_id);
    }

    fn owner_state(&mut self, owner: &Value, surface_id: &str) {
        for (field, expected, code, detail) in [
            (
                "path_state",
                "missing",
                "owner-path-missing",
                "Declared owner path is missing.",
            ),
            (
                "path_state",
                "unknown",
                "owner-path-unknown",
                "Declared owner path has not been checked.",
            ),
            (
                "package_state",
                "missing",
                "owner-undistributed",
                "Declared owner is absent from the distributable.",
            ),
            (
                "package_state",
                "unknown",
                "owner-distribution-unknown",
                "Owner distribution state is unknown.",
            ),
            (
                "authority_route",
                "detected",
                "authority-routing-detected",
                "Reconstructed owner routes into the authority.",
            ),
            (
                "authority_route",
                "unknown",
                "authority-routing-unknown",
                "Authority independence has not been established.",
            ),
        ] {
            if string(owner, field) == Some(expected) {
                self.reason(code, surface_id, detail);
            }
        }
    }

    fn evaluate_claims(
        &mut self,
        coverage: &Map<String, Value>,
        evidence_bundle: &EvidenceBundle,
        boundary: &Value,
        now: &Timestamp,
    ) {
        for claim_id in strings(boundary, "required_claim_ids") {
            let claims = values(coverage, "claims");
            let Some(claim) = claims
                .iter()
                .find(|claim| string(claim, "claim_id") == Some(&claim_id))
            else {
                self.reason(
                    "claim-missing",
                    &claim_id,
                    "Required finite claim is absent.",
                );
                continue;
            };
            let contracts: Vec<&Value> = values(coverage, "verifier_contracts")
                .into_iter()
                .filter(|contract| {
                    strings(contract, "claim_ids")
                        .iter()
                        .any(|id| id == &claim_id)
                })
                .collect();
            if contracts.is_empty() {
                self.reason(
                    "verifier-missing",
                    &claim_id,
                    "No verifier contract covers this claim.",
                );
                continue;
            }
            if contracts.len() > 1 {
                self.reason(
                    "verifier-duplicate",
                    &claim_id,
                    "Multiple verifier contracts claim primary coverage.",
                );
                continue;
            }
            self.evaluate_verifier(
                coverage,
                evidence_bundle,
                claim,
                contracts[0],
                &claim_id,
                now,
            );
        }
    }

    fn evaluate_verifier(
        &mut self,
        coverage: &Map<String, Value>,
        evidence_bundle: &EvidenceBundle,
        claim: &Value,
        contract: &Value,
        claim_id: &str,
        now: &Timestamp,
    ) {
        let verifier_id = string(contract, "verifier_id").unwrap_or_default();
        let observations = latest_observations(coverage, verifier_id);
        if observations.is_empty() {
            self.reason(
                "verifier-result-missing",
                claim_id,
                "Verifier has no recorded result.",
            );
            return;
        }
        for (result, _) in &observations {
            self.evidence(strings(result, "evidence_ids"));
        }
        if !observations
            .iter()
            .all(|(result, _)| same_assessment(result, observations[0].0))
        {
            self.reason(
                "verifier-result-ambiguous",
                claim_id,
                "Latest verifier observations have conflicting assessment content.",
            );
            return;
        }
        let Some((result, observed_at)) = observations
            .iter()
            .find(|(result, _)| comparable_evidence(result, contract, evidence_bundle))
        else {
            self.reason(
                "verifier-result-incompatible",
                claim_id,
                &format!(
                    "Latest verifier observation has no cited Evidence with comparable {} authority and confidence.",
                    string(contract, "authority").unwrap_or("unknown")
                ),
            );
            return;
        };
        if !verifier_matches(claim, contract, result, coverage) {
            self.reason("verifier-result-incompatible", claim_id, "Latest verifier result does not match current artifacts, owners, dimensions, authority, normalization, repeats, or contract.");
            return;
        }
        if is_stale(observed_at, now, number(contract, "max_age_ms")) {
            self.reason(
                "verifier-result-stale",
                claim_id,
                "Latest compatible verifier result is stale.",
            );
            return;
        }
        match string(result, "status") {
            Some("pass") => {}
            Some("fail") => self.reason(
                "verifier-failed",
                claim_id,
                "Latest compatible verifier result failed.",
            ),
            Some(status) => self.reason(
                "verifier-unknown",
                claim_id,
                &format!("Latest compatible verifier result is {status}."),
            ),
            None => self.reason(
                "verifier-unknown",
                claim_id,
                "Latest verifier result status is unknown.",
            ),
        }
    }

    fn evaluate_risks(&mut self, coverage: &Map<String, Value>, boundary: &Value) {
        for unknown in strings_map(coverage, "residual_unknown_ids") {
            if !strings(boundary, "allowed_unknown_ids")
                .iter()
                .any(|id| id == &unknown)
            {
                self.reason(
                    "active-unknown",
                    &unknown,
                    "Active residual unknown is not permitted by the completion boundary.",
                );
            }
        }
        let required_surfaces = strings(boundary, "required_surface_ids");
        let required_claims = strings(boundary, "required_claim_ids");
        for contradiction in values(coverage, "contradictions") {
            let affects_boundary = strings(contradiction, "surface_ids")
                .iter()
                .any(|id| required_surfaces.contains(id))
                || strings(contradiction, "claim_ids")
                    .iter()
                    .any(|id| required_claims.contains(id));
            if string(contradiction, "status") == Some("active") && affects_boundary {
                self.evidence(strings(contradiction, "evidence_ids"));
                self.reason(
                    "active-contradiction",
                    string(contradiction, "contradiction_id").unwrap_or_default(),
                    "Active contradiction affects the completion boundary.",
                );
            }
        }
    }

    fn evaluate_package_proofs(
        &mut self,
        coverage: &Map<String, Value>,
        evidence_bundle: &EvidenceBundle,
        boundary: &Value,
    ) {
        let required_artifacts = required_artifact_digests(coverage, boundary);
        for kind in strings(boundary, "required_package_proof_kinds") {
            let proofs: Vec<&Value> = values(coverage, "package_proofs")
                .into_iter()
                .filter(|proof| string(proof, "kind") == Some(&kind))
                .collect();
            let applicable = |proof: &Value| {
                required_artifacts
                    .iter()
                    .all(|digest| strings(proof, "artifact_sha256s").contains(digest))
                    && package_comparable(proof, evidence_bundle)
            };
            if let Some(proof) = proofs
                .iter()
                .find(|proof| string(proof, "status") == Some("pass") && applicable(*proof))
            {
                self.evidence(strings(proof, "evidence_ids"));
            } else if let Some(proof) = proofs
                .iter()
                .find(|proof| string(proof, "status") == Some("fail") && applicable(*proof))
            {
                self.evidence(strings(proof, "evidence_ids"));
                self.reason(
                    "package-proof-failed",
                    &kind,
                    "Required package or integration proof failed.",
                );
            } else if proofs.is_empty() {
                self.reason(
                    "package-proof-missing",
                    &kind,
                    "Required package or integration proof is missing.",
                );
            } else {
                for proof in proofs {
                    self.evidence(strings(proof, "evidence_ids"));
                }
                self.reason(
                    "package-proof-unknown",
                    &kind,
                    "Required package or integration proof has no qualifying passing Evidence.",
                );
            }
        }
    }

    fn evidence(&mut self, ids: Vec<String>) {
        self.evidence_ids.extend(ids);
    }

    fn reason(&mut self, code: &str, subject_id: &str, detail: &str) {
        self.reasons
            .push(json!({"code": code, "subject_id": subject_id, "detail": detail}));
    }

    fn finish(mut self, boundary: &Value) -> Value {
        self.reasons.sort_by(|left, right| {
            string(left, "code")
                .cmp(&string(right, "code"))
                .then_with(|| string(left, "subject_id").cmp(&string(right, "subject_id")))
        });
        let status = closure_status(&self.reasons);
        let probes = self
            .reasons
            .iter()
            .map(recommended_probe)
            .collect::<Vec<_>>();
        json!({"boundary_id": self.boundary_id, "status": status, "summary": {"required_surfaces": strings(boundary, "required_surface_ids").len(), "required_claims": strings(boundary, "required_claim_ids").len(), "reasons": self.reasons.len()}, "reasons": self.reasons, "recommended_probes": probes, "evidence_ids": self.evidence_ids.into_iter().collect::<Vec<_>>()})
    }
}

fn required_artifact_digests(coverage: &Map<String, Value>, boundary: &Value) -> Vec<String> {
    strings(boundary, "required_surface_ids")
        .into_iter()
        .filter_map(|surface_id| {
            let surface = values(coverage, "surfaces")
                .into_iter()
                .find(|item| string(item, "surface_id") == Some(&surface_id))?;
            let artifact_id = string(surface, "artifact_id")?;
            values(coverage, "artifacts")
                .into_iter()
                .find(|item| string(item, "artifact_id") == Some(artifact_id))
                .and_then(|artifact| string(artifact, "artifact_sha256").map(str::to_owned))
        })
        .collect()
}

fn verifier_matches(
    claim: &Value,
    contract: &Value,
    result: &Value,
    coverage: &Map<String, Value>,
) -> bool {
    let claim_id = string(claim, "claim_id").unwrap_or_default();
    let contract_claims = strings(contract, "claim_ids");
    let result_claims = strings(result, "covered_claim_ids");
    let required_dimensions = strings(claim, "required_dimensions");
    let contract_dimensions = strings(contract, "dimensions");
    let result_dimensions = strings(result, "covered_dimensions");
    let expected_artifacts = strings(claim, "surface_ids")
        .into_iter()
        .filter_map(|surface_id| {
            let surface = values(coverage, "surfaces")
                .into_iter()
                .find(|item| string(item, "surface_id") == Some(&surface_id))?;
            let artifact_id = string(surface, "artifact_id")?;
            values(coverage, "artifacts")
                .into_iter()
                .find(|item| string(item, "artifact_id") == Some(artifact_id))
                .and_then(|artifact| string(artifact, "artifact_sha256").map(str::to_owned))
        })
        .collect::<Vec<_>>();
    let expected_owners = strings(claim, "surface_ids")
        .into_iter()
        .flat_map(|surface_id| {
            values(coverage, "owners")
                .into_iter()
                .filter(move |owner| string(owner, "surface_id") == Some(surface_id.as_str()))
                .filter_map(|owner| owner.get("ownership"))
                .filter(|ownership| string(ownership, "disposition") == Some("implemented"))
                .filter_map(|ownership| string(ownership, "owner_sha256").map(str::to_owned))
        })
        .collect::<Vec<_>>();
    let artifact_digests = values(coverage, "artifacts")
        .into_iter()
        .filter_map(|artifact| string(artifact, "artifact_sha256").map(str::to_owned))
        .collect::<BTreeSet<_>>();
    let owner_digests = values(coverage, "owners")
        .into_iter()
        .filter_map(|owner| {
            let ownership = owner.get("ownership")?;
            (string(ownership, "disposition") == Some("implemented"))
                .then(|| string(ownership, "owner_sha256").map(str::to_owned))
                .flatten()
        })
        .collect::<BTreeSet<_>>();
    let result_artifacts = strings(result, "artifact_sha256s");
    let result_owners = strings(result, "owner_sha256s");
    result.get("contract_sha256") == contract.get("contract_sha256")
        && result.get("normalization_sha256") == contract.get("normalization_sha256")
        && contract_claims.iter().any(|item| item == claim_id)
        && result_claims.iter().any(|item| item == claim_id)
        && result_claims.iter().all(|id| contract_claims.contains(id))
        && required_dimensions
            .iter()
            .all(|id| contract_dimensions.contains(id) && result_dimensions.contains(id))
        && result_dimensions
            .iter()
            .all(|id| contract_dimensions.contains(id))
        && result_artifacts
            .iter()
            .all(|digest| artifact_digests.contains(digest))
        && expected_artifacts
            .iter()
            .all(|digest| result_artifacts.contains(digest))
        && result_owners
            .iter()
            .all(|digest| owner_digests.contains(digest))
        && expected_owners
            .iter()
            .all(|digest| result_owners.contains(digest))
        && number(result, "repeats") >= number(contract, "minimum_repeats")
        && string(claim, "required_authority") == string(contract, "authority")
}

fn comparable_evidence(result: &Value, contract: &Value, evidence_bundle: &EvidenceBundle) -> bool {
    let required = string(contract, "authority").unwrap_or_default();
    strings(result, "evidence_ids")
        .into_iter()
        .any(|id| evidence_matches(&id, required, evidence_bundle))
}

fn package_comparable(proof: &Value, evidence_bundle: &EvidenceBundle) -> bool {
    let requirements = package_authority_requirements(string(proof, "kind"));
    strings(proof, "evidence_ids").into_iter().any(|id| {
        requirements
            .iter()
            .any(|required| evidence_matches(&id, required, evidence_bundle))
    })
}

fn package_authority_requirements(kind: Option<&str>) -> &'static [&'static str] {
    match kind {
        Some("build") | Some("clean-install") | Some("runtime-routing") => &["live-observation"],
        Some("package-contents") | Some("authority-independence") => {
            &["shipped-artifact", "live-observation"]
        }
        _ => &[],
    }
}

fn evidence_matches(id: &str, required: &str, evidence_bundle: &EvidenceBundle) -> bool {
    let Some(record) = evidence_bundle
        .records()
        .iter()
        .find(|record| record.evidence_id() == id)
    else {
        return false;
    };
    let authority = json_string(record.authority().get());
    let confidence = json_string(record.confidence().get());
    let authority_ok = match required {
        "shipped-artifact" => authority.as_deref() == Some("shipped-artifact"),
        "controlled-replay" => authority.as_deref() == Some("controlled-replay"),
        "live-observation" => matches!(
            authority.as_deref(),
            Some("controlled-replay") | Some("external-service")
        ),
        "external" => authority.as_deref() == Some("external-service"),
        _ => false,
    };
    authority_ok
        && (confidence.as_deref() == Some("observed")
            || (required == "shipped-artifact" && confidence.as_deref() == Some("derived")))
}

fn same_assessment(left: &Value, right: &Value) -> bool {
    [
        "verifier_id",
        "contract_sha256",
        "status",
        "normalization_sha256",
        "repeats",
    ]
    .iter()
    .all(|field| left.get(*field) == right.get(*field))
        && unique_sorted_strings(left, "covered_claim_ids")
            == unique_sorted_strings(right, "covered_claim_ids")
        && unique_sorted_strings(left, "covered_dimensions")
            == unique_sorted_strings(right, "covered_dimensions")
        && unique_sorted_strings(left, "artifact_sha256s")
            == unique_sorted_strings(right, "artifact_sha256s")
        && unique_sorted_strings(left, "owner_sha256s")
            == unique_sorted_strings(right, "owner_sha256s")
}

fn unique_sorted_strings(value: &Value, field: &str) -> BTreeSet<String> {
    let mut items = strings(value, field);
    items.sort();
    items.into_iter().collect()
}

fn latest_observations<'a>(
    coverage: &'a Map<String, Value>,
    verifier_id: &str,
) -> Vec<(&'a Value, Timestamp)> {
    let mut latest: Vec<(&Value, Timestamp)> = Vec::new();

    for result in values(coverage, "verifier_results") {
        if string(result, "verifier_id") != Some(verifier_id) {
            continue;
        }

        let observed_at = string(result, "observed_at")
            .and_then(|value| coverage_input::parse_timestamp(value).ok())
            .expect("input validation parses every verifier timestamp");

        match latest.first() {
            None => latest.push((result, observed_at)),
            Some((_, latest_at)) => match compare_timestamps(&observed_at, latest_at) {
                std::cmp::Ordering::Greater => {
                    latest.clear();
                    latest.push((result, observed_at));
                }
                std::cmp::Ordering::Equal => latest.push((result, observed_at)),
                std::cmp::Ordering::Less => {}
            },
        }
    }

    latest
}

fn is_stale(observed_at: &Timestamp, now: &Timestamp, max_age_ms: f64) -> bool {
    if compare_timestamps(observed_at, now).is_gt() {
        return true;
    }

    let cutoff_epoch_millis = epoch_milliseconds(now) as f64 - max_age_ms;
    if cutoff_epoch_millis < -9_007_199_254_740_991.0 {
        return false;
    }

    let cutoff = timestamp_from_epoch_milliseconds(cutoff_epoch_millis as i128);
    compare_timestamps(observed_at, &cutoff).is_lt()
}

fn current_timestamp() -> Result<Timestamp, Failure> {
    let milliseconds = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => i128::try_from(duration.as_millis()).map_err(|_| clock_failure())?,
        Err(error) => {
            let milliseconds =
                i128::try_from(error.duration().as_millis()).map_err(|_| clock_failure())?;
            -milliseconds
        }
    };
    Ok(timestamp_from_epoch_milliseconds(milliseconds))
}

fn timestamp_from_epoch_milliseconds(milliseconds: i128) -> Timestamp {
    let epoch_seconds = milliseconds.div_euclid(1_000);
    let millisecond_digits = milliseconds.rem_euclid(1_000);
    let fraction = format!("{millisecond_digits:03}")
        .trim_end_matches('0')
        .to_owned();

    Timestamp {
        epoch_seconds,
        fraction,
    }
}

fn epoch_milliseconds(timestamp: &Timestamp) -> i128 {
    let fraction_milliseconds = timestamp
        .fraction
        .chars()
        .take(3)
        .fold(0_i128, |value, digit| {
            value * 10 + i128::from(digit as u8 - b'0')
        });
    let padded_milliseconds = match timestamp.fraction.len().min(3) {
        0 => 0,
        1 => fraction_milliseconds * 100,
        2 => fraction_milliseconds * 10,
        _ => fraction_milliseconds,
    };

    timestamp.epoch_seconds * 1_000 + padded_milliseconds
}

fn json_string(raw: &str) -> Option<String> {
    serde_json::from_str(raw).ok()
}

fn closure_status(reasons: &[Value]) -> &str {
    if reasons.is_empty() {
        return "ready";
    }
    if reasons.iter().any(|reason| {
        matches!(
            string(reason, "code"),
            Some(
                "verifier-failed"
                    | "active-contradiction"
                    | "authority-routing-detected"
                    | "owner-path-missing"
                    | "owner-undistributed"
                    | "package-proof-failed"
            )
        )
    }) {
        return "failed";
    }
    if reasons.iter().any(|reason| {
        matches!(
            string(reason, "code"),
            Some(
                "verifier-unknown"
                    | "verifier-result-stale"
                    | "verifier-result-incompatible"
                    | "verifier-result-ambiguous"
                    | "active-unknown"
                    | "owner-path-unknown"
                    | "owner-distribution-unknown"
                    | "authority-routing-unknown"
                    | "package-proof-unknown"
            )
        )
    }) {
        return "unknown";
    }
    "partial"
}
fn recommended_probe(reason: &Value) -> Value {
    let code = string(reason, "code").unwrap_or_default();
    let operation = if code.starts_with("owner-") || code.starts_with("authority-routing") {
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
    };
    json!({"operation": operation, "subject_id": reason["subject_id"], "rationale": reason["detail"]})
}
fn values<'a>(object: &'a Map<String, Value>, field: &str) -> Vec<&'a Value> {
    object
        .get(field)
        .and_then(Value::as_array)
        .map(|items| items.iter().collect())
        .unwrap_or_default()
}
fn strings(value: &Value, field: &str) -> Vec<String> {
    value
        .as_object()
        .map(|object| {
            values(object, field)
                .into_iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}
fn strings_map(object: &Map<String, Value>, field: &str) -> Vec<String> {
    values(object, field)
        .into_iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}
fn string<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value.get(field).and_then(Value::as_str)
}
fn number(value: &Value, field: &str) -> f64 {
    value.get(field).and_then(Value::as_f64).unwrap_or_default()
}

fn clock_failure() -> Failure {
    Failure::new(
        "runtime_error",
        "clock_unavailable",
        "The system clock could not be represented for freshness evaluation".into(),
        false,
        "Retry reconstruction coverage evaluation when the system clock is available.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

fn invalid_evaluation_timestamp() -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "The evaluation timestamp must be an ISO date-time with an explicit offset".into(),
        false,
        "Provide a schema-valid evaluation timestamp.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rea_core::{canonical_json, evidence::record::EvidenceRecord};
    use serde_json::Value;

    const ARTIFACT_SHA256: &str =
        "1111111111111111111111111111111111111111111111111111111111111111";
    const ENVIRONMENT_SHA256: &str =
        "2222222222222222222222222222222222222222222222222222222222222222";
    const OWNER_SHA256: &str = "3333333333333333333333333333333333333333333333333333333333333333";
    const NORMALIZATION_SHA256: &str =
        "4444444444444444444444444444444444444444444444444444444444444444";

    fn input() -> Value {
        let records = fixture_records();
        let evidence_bundle = fixture_bundle_value(&records);
        let contract = fixture_contract();
        let record_id = |character: &str| {
            records
                .iter()
                .find(|record| record.operation_matches(&format!("fixture-{character}")))
                .expect("fixture Evidence")
                .evidence_id()
                .to_owned()
        };

        serde_json::json!({
            "coverage": {
                "evidence_bundle": evidence_bundle,
                "artifacts": [{
                    "artifact_id": "authority.v1",
                    "artifact_sha256": ARTIFACT_SHA256,
                    "version": "1.0.0",
                    "environment_sha256": ENVIRONMENT_SHA256,
                    "evidence_ids": [record_id("1")]
                }],
                "surfaces": [{
                    "surface_id": "cli.help",
                    "family": "cli-command",
                    "artifact_id": "authority.v1",
                    "occurrence_id": "occ-help",
                    "location": "bin/app --help",
                    "authority": "observed",
                    "dependency_surface_ids": [],
                    "evidence_ids": [record_id("2")]
                }],
                "owners": [{
                    "surface_id": "cli.help",
                    "ownership": {
                        "disposition": "implemented",
                        "owner_path": "src/cli.ts",
                        "owner_export": "registerHelp",
                        "owner_sha256": OWNER_SHA256,
                        "path_state": "present",
                        "package_state": "distributed",
                        "authority_route": "none"
                    }
                }],
                "claims": [{
                    "claim_id": "claim.cli.help",
                    "title": "Help output and exit behavior match",
                    "kind": "behavioral",
                    "surface_ids": ["cli.help"],
                    "required_dimensions": ["output", "exit"],
                    "required_authority": "controlled-replay"
                }],
                "verifier_contracts": [contract],
                "verifier_results": [{
                    "verifier_id": "verify.cli.help",
                    "contract_sha256": contract["contract_sha256"],
                    "observed_at": "2026-07-16T11:00:00.000Z",
                    "status": "pass",
                    "covered_claim_ids": ["claim.cli.help"],
                    "covered_dimensions": ["output", "exit"],
                    "artifact_sha256s": [ARTIFACT_SHA256],
                    "owner_sha256s": [OWNER_SHA256],
                    "normalization_sha256": NORMALIZATION_SHA256,
                    "repeats": 2,
                    "evidence_ids": [record_id("3")]
                }],
                "residual_unknown_ids": [],
                "contradictions": [],
                "package_proofs": [
                    {
                        "proof_id": "proof.clean-install",
                        "kind": "clean-install",
                        "status": "pass",
                        "artifact_sha256s": [ARTIFACT_SHA256],
                        "evidence_ids": [record_id("4")]
                    },
                    {
                        "proof_id": "proof.authority-independence",
                        "kind": "authority-independence",
                        "status": "pass",
                        "artifact_sha256s": [ARTIFACT_SHA256],
                        "evidence_ids": [record_id("5")]
                    }
                ],
                "boundaries": [{
                    "boundary_id": "replacement.cli",
                    "title": "CLI replacement",
                    "required_surface_ids": ["cli.help"],
                    "required_claim_ids": ["claim.cli.help"],
                    "required_package_proof_kinds": ["clean-install", "authority-independence"],
                    "allowed_dispositions": [],
                    "allowed_unknown_ids": []
                }]
            },
            "boundary_id": "replacement.cli"
        })
    }

    fn fixture_records() -> Vec<EvidenceRecord> {
        ["1", "2", "3", "4", "5"]
            .into_iter()
            .map(|character| {
                let authority = match character {
                    "3" | "4" => "controlled-replay",
                    _ => "shipped-artifact",
                };
                let unsigned = serde_json::json!({
                    "subject": null,
                    "provider": {"id": "fixture", "name": "Fixture", "version": "1"},
                    "analysis_profile": null,
                    "predicate_type": "rea.coverage-fixture",
                    "operation": format!("fixture-{character}"),
                    "parameters": {},
                    "raw_result": null,
                    "normalized_result": {"character": character},
                    "confidence": "observed",
                    "authority": authority,
                    "environment": null,
                    "limitations": [],
                    "relationship_coverage": null,
                    "locations": [],
                    "evidence_links": []
                });
                let raw =
                    serde_json::value::to_raw_value(&unsigned).expect("unsigned Evidence JSON");
                EvidenceRecord::create_unsigned(&raw).expect("authenticated fixture Evidence")
            })
            .collect()
    }

    fn fixture_bundle_value(records: &[EvidenceRecord]) -> Value {
        let mut records = records.iter().collect::<Vec<_>>();
        records.sort_by(|left, right| left.evidence_id().cmp(right.evidence_id()));

        let providers = records
            .first()
            .map(|record| serde_json::from_str(record.provider_manifest().get()))
            .transpose()
            .expect("fixture provider manifest");
        let scenarios = records
            .iter()
            .filter_map(|record| record.scenario_manifest())
            .map(|manifest| serde_json::from_str(manifest.get()))
            .collect::<Result<Vec<Value>, _>>()
            .expect("fixture scenario manifests");
        let record_values = records
            .iter()
            .map(|record| serde_json::from_str(record.raw().get()))
            .collect::<Result<Vec<Value>, _>>()
            .expect("fixture Evidence records");

        serde_json::json!({
            "artifacts": [],
            "providers": providers.into_iter().collect::<Vec<Value>>(),
            "environments": [],
            "scenarios": scenarios,
            "captures": [],
            "unknowns": [],
            "records": record_values
        })
    }

    fn fixture_contract() -> Value {
        let mut contract = serde_json::json!({
            "verifier_id": "verify.cli.help",
            "claim_ids": ["claim.cli.help"],
            "dimensions": ["output", "exit"],
            "authority": "controlled-replay",
            "max_age_ms": 86_400_000,
            "minimum_repeats": 2,
            "normalization_sha256": NORMALIZATION_SHA256,
            "normalization_removes_dimensions": false
        });
        contract["contract_sha256"] = serde_json::json!(
            canonical_json::digest(&contract).expect("canonical verifier contract digest")
        );
        contract
    }

    fn evaluate_at(input: &Value, now: &str) -> Value {
        let bundle = coverage_input::validate(input).expect("valid reconstruction coverage input");
        let now = coverage_input::parse_timestamp(now).expect("valid fixed evaluation timestamp");
        evaluate_validated(input, &bundle, &now)
    }

    fn verifier_result_mut(input: &mut Value) -> &mut Value {
        &mut input["coverage"]["verifier_results"][0]
    }

    #[test]
    fn complete_evidence_backed_boundary_is_ready() {
        let input = input();
        validate_input(&input).expect("valid reconstruction coverage input");
        assert_eq!(
            evaluate_at(&input, "2026-07-16T12:00:00Z")["status"],
            "ready"
        );
        assert_eq!(
            evaluate(&input).expect("evaluated coverage")["boundary_id"],
            "replacement.cli"
        );
    }

    #[test]
    fn explicit_evaluation_timestamp_is_available_at_application_boundary() {
        let input = input();

        let result = super::evaluate_at(&input, "2026-07-16T12:00:00Z")
            .expect("explicit evaluation timestamp should be accepted");

        assert_eq!(result["status"], "ready");
    }

    #[test]
    fn rejects_invalid_explicit_evaluation_timestamp() {
        let failure = super::evaluate_at(&input(), "2026-07-16T12:00")
            .expect_err("missing offset should be rejected");

        assert_eq!(failure.code(), "invalid_request");
        assert_eq!(failure.operation(), Some(OPERATION));
    }

    #[test]
    fn rejects_undeclared_boundary() {
        let mut invalid_input = input();
        invalid_input["boundary_id"] = serde_json::json!("replacement.mcp");
        assert!(validate_input(&invalid_input).is_err());
    }

    #[test]
    fn rejects_nonempty_unknown_boundary_after_schema_validation() {
        let mut invalid_input = input();
        invalid_input["boundary_id"] = serde_json::json!(" ");

        let failure = validate_input(&invalid_input).expect_err("unknown boundary");

        assert_eq!(failure.code(), "invalid_request");
        assert_eq!(failure.operation(), Some(OPERATION));
    }

    #[test]
    fn rejects_missing_coverage_collection() {
        let mut invalid_input = input();
        invalid_input["coverage"]["claims"] = serde_json::json!({});
        assert!(validate_input(&invalid_input).is_err());
    }

    #[test]
    fn selects_latest_verifier_observation_by_offset_instant() {
        let mut input = input();
        verifier_result_mut(&mut input)["observed_at"] = serde_json::json!("2026-07-16T08:00:00Z");
        let mut later = verifier_result_mut(&mut input).clone();
        later["observed_at"] = serde_json::json!("2026-07-16T04:00:00.0009-05:00");
        later["status"] = serde_json::json!("unknown");
        input["coverage"]["verifier_results"]
            .as_array_mut()
            .expect("verifier result array")
            .push(later);

        let result = evaluate_at(&input, "2026-07-16T12:00:00Z");
        assert_eq!(result["status"], "unknown");
        assert!(result["reasons"].to_string().contains("verifier-unknown"));
    }

    #[test]
    fn equal_latest_instants_with_different_assessments_are_ambiguous() {
        let mut input = input();
        verifier_result_mut(&mut input)["observed_at"] = serde_json::json!("2026-07-16T08:00:00Z");
        let mut tied = verifier_result_mut(&mut input).clone();
        tied["observed_at"] = serde_json::json!("2026-07-16T10:00:00+02:00");
        tied["status"] = serde_json::json!("unknown");
        input["coverage"]["verifier_results"]
            .as_array_mut()
            .expect("verifier result array")
            .push(tied);

        let result = evaluate_at(&input, "2026-07-16T12:00:00Z");
        assert_eq!(result["status"], "unknown");
        assert!(
            result["reasons"]
                .to_string()
                .contains("verifier-result-ambiguous")
        );
    }

    #[test]
    fn stale_failed_verifier_result_reports_staleness_without_failure() {
        let mut input = input();
        verifier_result_mut(&mut input)["observed_at"] = serde_json::json!("2026-07-14T11:00:00Z");
        verifier_result_mut(&mut input)["status"] = serde_json::json!("fail");

        let result = evaluate_at(&input, "2026-07-16T12:00:00Z");
        let reason_codes = result["reasons"]
            .as_array()
            .expect("reason list")
            .iter()
            .filter_map(|reason| reason["code"].as_str())
            .collect::<Vec<_>>();
        assert!(reason_codes.contains(&"verifier-result-stale"));
        assert!(!reason_codes.contains(&"verifier-failed"));
    }

    #[test]
    fn rejects_tampered_evidence_even_when_its_reference_is_well_formed() {
        let mut input = input();
        input["coverage"]["evidence_bundle"]["records"][0]["normalized_result"] =
            serde_json::json!({"forged": true});

        assert!(validate_input(&input).is_err());
    }

    #[test]
    fn rejects_missing_referenced_evidence() {
        let mut input = input();
        input["coverage"]["artifacts"][0]["evidence_ids"][0] =
            serde_json::json!(format!("ev_{}", "a".repeat(64)));

        assert!(validate_input(&input).is_err());
    }
}
