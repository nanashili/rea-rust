//! Strict input ownership for reconstruction coverage evaluation.
//!
//! This boundary mirrors the TypeScript Zod schemas, authenticates the inline
//! Evidence bundle and validates the cross-references owned by this boundary.

use rea_core::{
    canonical_json,
    evidence::bundle::{EvidenceBundle, EvidenceBundleError},
    failure::{Detail, Failure},
};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

use crate::reconstruction::coverage::OPERATION;

pub(crate) fn validate(input: &Value) -> Result<EvidenceBundle, Failure> {
    let input = strict_object(input, "input", &["coverage", "boundary_id"])?;
    let requested_boundary = text(input, "boundary_id", "boundary_id")?;
    if requested_boundary.is_empty() {
        return Err(invalid("boundary_id must be a non-empty string"));
    }

    let coverage_value = input
        .get("coverage")
        .ok_or_else(|| invalid("coverage is required"))?;
    let coverage = strict_object(
        coverage_value,
        "coverage",
        &[
            "evidence_bundle",
            "artifacts",
            "surfaces",
            "owners",
            "claims",
            "verifier_contracts",
            "verifier_results",
            "residual_unknown_ids",
            "contradictions",
            "package_proofs",
            "boundaries",
        ],
    )?;

    let bundle = authenticate_evidence_bundle(coverage)?;
    validate_artifacts(coverage)?;
    validate_surfaces(coverage)?;
    validate_owners(coverage)?;
    validate_claims(coverage)?;
    validate_verifier_contracts(coverage)?;
    validate_verifier_results(coverage)?;
    validate_unknown_ids(coverage)?;
    validate_contradictions(coverage)?;
    validate_package_proofs(coverage)?;
    validate_boundaries(coverage)?;

    validate_cross_references(coverage, &bundle)?;

    if !array(coverage, "boundaries")?.iter().any(|boundary| {
        boundary.get("boundary_id").and_then(Value::as_str) == Some(requested_boundary)
    }) {
        return Err(invalid("Unknown reconstruction boundary."));
    }

    Ok(bundle)
}

fn authenticate_evidence_bundle(coverage: &Map<String, Value>) -> Result<EvidenceBundle, Failure> {
    let value = coverage
        .get("evidence_bundle")
        .ok_or_else(|| invalid("coverage.evidence_bundle is required"))?;
    let raw = serde_json::value::to_raw_value(value)
        .map_err(|error| invalid(&format!("coverage.evidence_bundle is invalid: {error}")))?;
    EvidenceBundle::parse(&raw).map_err(|error| match error {
        EvidenceBundleError::RecordAt {
            error: rea_core::evidence::record::EvidenceRecordError::SemanticIdMismatch,
            ..
        } => invalid("Evidence bundle contains an unauthenticated Evidence record."),
        _ => invalid(&format!("Evidence bundle is invalid: {error}")),
    })
}

fn validate_artifacts(coverage: &Map<String, Value>) -> Result<(), Failure> {
    let mut artifact_ids = BTreeSet::new();
    for artifact in array(coverage, "artifacts")? {
        let artifact = strict_object(
            artifact,
            "artifact",
            &[
                "artifact_id",
                "artifact_sha256",
                "version",
                "environment_sha256",
                "evidence_ids",
            ],
        )?;
        unique_identifier(artifact, "artifact_id", &mut artifact_ids)?;
        digest(artifact, "artifact_sha256")?;
        non_empty_trimmed(
            text(artifact, "version", "artifact.version")?,
            "artifact.version",
        )?;
        digest(artifact, "environment_sha256")?;
        evidence_id_array(artifact, "evidence_ids", true)?;
    }
    Ok(())
}

fn validate_surfaces(coverage: &Map<String, Value>) -> Result<(), Failure> {
    let mut surface_ids = BTreeSet::new();
    for surface in array(coverage, "surfaces")? {
        let surface = strict_object(
            surface,
            "surface",
            &[
                "surface_id",
                "family",
                "artifact_id",
                "occurrence_id",
                "location",
                "authority",
                "dependency_surface_ids",
                "evidence_ids",
            ],
        )?;
        unique_identifier(surface, "surface_id", &mut surface_ids)?;
        non_empty_trimmed(text(surface, "family", "surface.family")?, "surface.family")?;
        identifier(text(surface, "artifact_id", "surface.artifact_id")?)?;
        nullable_non_empty_text(surface, "occurrence_id", "surface.occurrence_id")?;
        non_empty_trimmed(
            text(surface, "location", "surface.location")?,
            "surface.location",
        )?;
        enumeration(
            surface,
            "authority",
            &["observed", "derived", "inferred", "historical", "external"],
        )?;
        string_array(surface, "dependency_surface_ids", false, identifier)?;
        evidence_id_array(surface, "evidence_ids", true)?;
    }
    Ok(())
}

fn validate_owners(coverage: &Map<String, Value>) -> Result<(), Failure> {
    for owner in array(coverage, "owners")? {
        let owner = strict_object(owner, "owner", &["surface_id", "ownership"])?;
        identifier(text(owner, "surface_id", "owner.surface_id")?)?;
        let ownership = owner
            .get("ownership")
            .ok_or_else(|| invalid("owner.ownership is required"))?;
        let disposition = ownership
            .get("disposition")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("owner.ownership.disposition must be a string"))?;
        match disposition {
            "implemented" => {
                let ownership = strict_object(
                    ownership,
                    "implemented ownership",
                    &[
                        "disposition",
                        "owner_path",
                        "owner_export",
                        "owner_sha256",
                        "path_state",
                        "package_state",
                        "authority_route",
                    ],
                )?;
                non_empty_trimmed(text(ownership, "owner_path", "owner_path")?, "owner_path")?;
                nullable_non_empty_text(ownership, "owner_export", "owner_export")?;
                digest(ownership, "owner_sha256")?;
                enumeration(ownership, "path_state", &["present", "missing", "unknown"])?;
                enumeration(
                    ownership,
                    "package_state",
                    &["distributed", "missing", "unknown"],
                )?;
                enumeration(
                    ownership,
                    "authority_route",
                    &["none", "detected", "unknown"],
                )?;
            }
            "external" | "non-goal" => {
                let ownership = strict_object(
                    ownership,
                    "external ownership",
                    &["disposition", "rationale"],
                )?;
                non_empty_trimmed(text(ownership, "rationale", "rationale")?, "rationale")?;
            }
            _ => return Err(invalid("owner.ownership.disposition is unsupported")),
        }
    }
    Ok(())
}

fn validate_claims(coverage: &Map<String, Value>) -> Result<(), Failure> {
    let mut claim_ids = BTreeSet::new();
    for claim in array(coverage, "claims")? {
        let claim = strict_object(
            claim,
            "claim",
            &[
                "claim_id",
                "title",
                "kind",
                "surface_ids",
                "required_dimensions",
                "required_authority",
            ],
        )?;
        unique_identifier(claim, "claim_id", &mut claim_ids)?;
        non_empty_trimmed(text(claim, "title", "claim.title")?, "claim.title")?;
        non_empty_trimmed(text(claim, "kind", "claim.kind")?, "claim.kind")?;
        string_array(claim, "surface_ids", true, identifier)?;
        string_array(claim, "required_dimensions", true, identifier)?;
        enumeration(
            claim,
            "required_authority",
            &[
                "shipped-artifact",
                "controlled-replay",
                "live-observation",
                "external",
            ],
        )?;
    }
    Ok(())
}

fn validate_verifier_contracts(coverage: &Map<String, Value>) -> Result<(), Failure> {
    let mut verifier_ids = BTreeSet::new();
    for contract in array(coverage, "verifier_contracts")? {
        let contract = strict_object(
            contract,
            "verifier contract",
            &[
                "verifier_id",
                "claim_ids",
                "dimensions",
                "authority",
                "max_age_ms",
                "minimum_repeats",
                "normalization_sha256",
                "normalization_removes_dimensions",
                "contract_sha256",
            ],
        )?;
        unique_identifier(contract, "verifier_id", &mut verifier_ids)?;
        string_array(contract, "claim_ids", true, identifier)?;
        string_array(contract, "dimensions", true, identifier)?;
        enumeration(
            contract,
            "authority",
            &[
                "shipped-artifact",
                "controlled-replay",
                "live-observation",
                "external",
            ],
        )?;
        positive_integer(contract, "max_age_ms")?;
        positive_integer(contract, "minimum_repeats")?;
        digest(contract, "normalization_sha256")?;
        if contract.get("normalization_removes_dimensions") != Some(&Value::Bool(false)) {
            return Err(invalid("normalization_removes_dimensions must be false"));
        }
        validate_contract_digest(contract)?;
    }
    Ok(())
}

fn validate_verifier_results(coverage: &Map<String, Value>) -> Result<(), Failure> {
    for result in array(coverage, "verifier_results")? {
        let result = strict_object(
            result,
            "verifier result",
            &[
                "verifier_id",
                "contract_sha256",
                "observed_at",
                "status",
                "covered_claim_ids",
                "covered_dimensions",
                "artifact_sha256s",
                "owner_sha256s",
                "normalization_sha256",
                "repeats",
                "evidence_ids",
            ],
        )?;
        identifier(text(result, "verifier_id", "verifier_id")?)?;
        digest(result, "contract_sha256")?;
        parse_timestamp(text(result, "observed_at", "observed_at")?)
            .map_err(|_| invalid("observed_at must be an ISO date-time with an explicit offset"))?;
        enumeration(
            result,
            "status",
            &[
                "pass",
                "fail",
                "unknown",
                "unsupported",
                "truncated",
                "skipped",
            ],
        )?;
        string_array(result, "covered_claim_ids", true, identifier)?;
        string_array(result, "covered_dimensions", true, identifier)?;
        digest_array(result, "artifact_sha256s", true)?;
        digest_array(result, "owner_sha256s", false)?;
        digest(result, "normalization_sha256")?;
        positive_integer(result, "repeats")?;
        evidence_id_array(result, "evidence_ids", true)?;
    }
    Ok(())
}

fn validate_unknown_ids(coverage: &Map<String, Value>) -> Result<(), Failure> {
    string_array(coverage, "residual_unknown_ids", false, identifier).map(|_| ())
}

fn validate_contradictions(coverage: &Map<String, Value>) -> Result<(), Failure> {
    let mut ids = BTreeSet::new();
    for contradiction in array(coverage, "contradictions")? {
        let contradiction = strict_object(
            contradiction,
            "contradiction",
            &[
                "contradiction_id",
                "status",
                "surface_ids",
                "claim_ids",
                "evidence_ids",
            ],
        )?;
        unique_identifier(contradiction, "contradiction_id", &mut ids)?;
        enumeration(contradiction, "status", &["active", "resolved"])?;
        string_array(contradiction, "surface_ids", false, identifier)?;
        string_array(contradiction, "claim_ids", false, identifier)?;
        evidence_id_array(contradiction, "evidence_ids", true)?;
        if array(contradiction, "evidence_ids")?.len() < 2 {
            return Err(invalid(
                "contradiction.evidence_ids requires at least two IDs",
            ));
        }
    }
    Ok(())
}

fn validate_package_proofs(coverage: &Map<String, Value>) -> Result<(), Failure> {
    let mut ids = BTreeSet::new();
    for proof in array(coverage, "package_proofs")? {
        let proof = strict_object(
            proof,
            "package proof",
            &[
                "proof_id",
                "kind",
                "status",
                "artifact_sha256s",
                "evidence_ids",
            ],
        )?;
        unique_identifier(proof, "proof_id", &mut ids)?;
        enumeration(
            proof,
            "kind",
            &[
                "build",
                "clean-install",
                "package-contents",
                "runtime-routing",
                "authority-independence",
            ],
        )?;
        enumeration(
            proof,
            "status",
            &["pass", "fail", "unknown", "unsupported", "skipped"],
        )?;
        digest_array(proof, "artifact_sha256s", true)?;
        evidence_id_array(proof, "evidence_ids", true)?;
    }
    Ok(())
}

fn validate_boundaries(coverage: &Map<String, Value>) -> Result<(), Failure> {
    let mut ids = BTreeSet::new();
    for boundary in array(coverage, "boundaries")? {
        let boundary = strict_object(
            boundary,
            "boundary",
            &[
                "boundary_id",
                "title",
                "required_surface_ids",
                "required_claim_ids",
                "required_package_proof_kinds",
                "allowed_dispositions",
                "allowed_unknown_ids",
            ],
        )?;
        unique_identifier(boundary, "boundary_id", &mut ids)?;
        non_empty_trimmed(text(boundary, "title", "boundary.title")?, "boundary.title")?;
        string_array(boundary, "required_surface_ids", true, identifier)?;
        string_array(boundary, "required_claim_ids", true, identifier)?;
        string_array(boundary, "required_package_proof_kinds", true, |value| {
            one_of(
                value,
                &[
                    "build",
                    "clean-install",
                    "package-contents",
                    "runtime-routing",
                    "authority-independence",
                ],
            )
        })?;
        string_array(boundary, "allowed_dispositions", false, |value| {
            one_of(value, &["external", "non-goal"])
        })?;
        string_array(boundary, "allowed_unknown_ids", false, identifier)?;
    }
    Ok(())
}

fn validate_cross_references(
    coverage: &Map<String, Value>,
    bundle: &EvidenceBundle,
) -> Result<(), Failure> {
    let artifact_ids = collect_ids(coverage, "artifacts", "artifact_id")?;
    let surface_ids = collect_ids(coverage, "surfaces", "surface_id")?;
    let claim_ids = collect_ids(coverage, "claims", "claim_id")?;
    let contract_ids = collect_ids(coverage, "verifier_contracts", "verifier_id")?;
    let record_ids: BTreeSet<&str> = bundle
        .records()
        .iter()
        .map(|record| record.evidence_id())
        .collect();
    let unknown_ids: BTreeSet<&str> = bundle
        .unknowns()
        .iter()
        .map(|unknown| unknown.unknown_id())
        .collect();

    for surface in array(coverage, "surfaces")? {
        let surface_id = required_string(surface, "surface_id")?;
        let artifact_id = required_string(surface, "artifact_id")?;
        if !artifact_ids.contains(artifact_id) {
            return Err(invalid(&format!(
                "Surface artifact is missing: {surface_id}"
            )));
        }
    }
    for owner in array(coverage, "owners")? {
        if !surface_ids.contains(required_string(owner, "surface_id")?) {
            return Err(invalid("Owner references an unknown surface"));
        }
    }
    for claim in array(coverage, "claims")? {
        for surface_id in strings(claim, "surface_ids")? {
            if !surface_ids.contains(surface_id) {
                return Err(invalid(&format!(
                    "Claim surface is missing: {}",
                    required_string(claim, "claim_id")?
                )));
            }
        }
    }
    for contract in array(coverage, "verifier_contracts")? {
        for claim_id in strings(contract, "claim_ids")? {
            if !claim_ids.contains(claim_id) {
                return Err(invalid(&format!(
                    "Verifier claim is missing: {}",
                    required_string(contract, "verifier_id")?
                )));
            }
        }
    }
    for result in array(coverage, "verifier_results")? {
        if !contract_ids.contains(required_string(result, "verifier_id")?) {
            return Err(invalid(&format!(
                "Verifier result contract is missing: {}",
                required_string(result, "verifier_id")?
            )));
        }
    }

    for record_id in referenced_evidence_ids(coverage)? {
        if !record_ids.contains(record_id) {
            return Err(invalid(&format!(
                "Coverage workspace Evidence is missing: {record_id}"
            )));
        }
    }
    for unknown_id in string_array(coverage, "residual_unknown_ids", false, identifier)? {
        if !unknown_ids.contains(unknown_id.as_str()) {
            return Err(invalid(&format!(
                "Coverage workspace residual unknown is missing: {unknown_id}"
            )));
        }
    }
    Ok(())
}

fn validate_contract_digest(contract: &Map<String, Value>) -> Result<(), Failure> {
    let mut base = contract.clone();
    let expected = base
        .remove("contract_sha256")
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or_else(|| invalid("contract_sha256 must be a digest"))?;
    let actual = canonical_json::digest(&Value::Object(base)).map_err(|error| {
        invalid(&format!(
            "Verifier contract cannot be canonicalized: {error}"
        ))
    })?;
    if actual != expected {
        return Err(invalid("Verifier contract digest is invalid"));
    }
    Ok(())
}

fn referenced_evidence_ids(coverage: &Map<String, Value>) -> Result<Vec<&str>, Failure> {
    let mut ids = Vec::new();
    for (collection, field) in [
        ("artifacts", "evidence_ids"),
        ("surfaces", "evidence_ids"),
        ("verifier_results", "evidence_ids"),
        ("contradictions", "evidence_ids"),
        ("package_proofs", "evidence_ids"),
    ] {
        for item in array(coverage, collection)? {
            ids.extend(strings(item, field)?);
        }
    }
    Ok(ids)
}

fn collect_ids<'a>(
    coverage: &'a Map<String, Value>,
    collection: &str,
    key: &str,
) -> Result<BTreeSet<&'a str>, Failure> {
    array(coverage, collection)?
        .iter()
        .map(|item| required_string(item, key))
        .collect()
}

fn strict_object<'a>(
    value: &'a Value,
    label: &str,
    required: &[&str],
) -> Result<&'a Map<String, Value>, Failure> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid(&format!("{label} must be an object")))?;
    for key in object.keys() {
        if !required.contains(&key.as_str()) {
            return Err(invalid(&format!("Unrecognized {label} field: {key}")));
        }
    }
    for key in required {
        if !object.contains_key(*key) {
            return Err(invalid(&format!("{label}.{key} is required")));
        }
    }
    Ok(object)
}

fn array<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a Vec<Value>, Failure> {
    object
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(&format!("{field} must be an array")))
}

fn text<'a>(object: &'a Map<String, Value>, field: &str, label: &str) -> Result<&'a str, Failure> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(&format!("{label} must be a string")))
}

fn required_string<'a>(value: &'a Value, field: &str) -> Result<&'a str, Failure> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(&format!("{field} must be a string")))
}

fn non_empty_trimmed(value: &str, label: &str) -> Result<(), Failure> {
    if value.trim().is_empty() {
        return Err(invalid(&format!("{label} must be a non-empty string")));
    }
    Ok(())
}

fn identifier(value: &str) -> Result<(), Failure> {
    let mut chars = value.chars();
    let first = chars
        .next()
        .ok_or_else(|| invalid("identifier must be non-empty"))?;
    if !first.is_ascii_alphabetic()
        || value.len() > 200
        || !chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | ':' | '/' | '-'))
    {
        return Err(invalid("identifier has an invalid format"));
    }
    Ok(())
}

fn digest(object: &Map<String, Value>, field: &str) -> Result<(), Failure> {
    let value = text(object, field, field)?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(invalid(&format!(
            "{field} must be a lowercase SHA-256 digest"
        )));
    }
    Ok(())
}

fn digest_array(
    object: &Map<String, Value>,
    field: &str,
    require_non_empty: bool,
) -> Result<Vec<String>, Failure> {
    let items = array(object, field)?;
    if require_non_empty && items.is_empty() {
        return Err(invalid(&format!("{field} must contain at least one item")));
    }
    for item in items {
        let value = item
            .as_str()
            .ok_or_else(|| invalid(&format!("{field} values must be strings")))?;
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(invalid(&format!(
                "{field} values must be lowercase SHA-256 digests"
            )));
        }
    }
    Ok(items
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect())
}

fn evidence_id_array(
    object: &Map<String, Value>,
    field: &str,
    require_non_empty: bool,
) -> Result<Vec<String>, Failure> {
    string_array(object, field, require_non_empty, |value| {
        if value.len() != 67
            || !value.starts_with("ev_")
            || !value[3..]
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(invalid("Evidence ID has an invalid format"));
        }
        Ok(())
    })
}

fn string_array(
    object: &Map<String, Value>,
    field: &str,
    require_non_empty: bool,
    validate: impl Fn(&str) -> Result<(), Failure>,
) -> Result<Vec<String>, Failure> {
    let items = array(object, field)?;
    if require_non_empty && items.is_empty() {
        return Err(invalid(&format!("{field} must contain at least one item")));
    }
    let mut output = Vec::with_capacity(items.len());
    for item in items {
        let value = item
            .as_str()
            .ok_or_else(|| invalid(&format!("{field} values must be strings")))?;
        validate(value)?;
        output.push(value.to_owned());
    }
    Ok(output)
}

fn nullable_non_empty_text(
    object: &Map<String, Value>,
    field: &str,
    label: &str,
) -> Result<(), Failure> {
    match object.get(field) {
        Some(Value::Null) => Ok(()),
        Some(Value::String(value)) => non_empty_trimmed(value, label),
        _ => Err(invalid(&format!("{label} must be a string or null"))),
    }
}

fn enumeration(object: &Map<String, Value>, field: &str, allowed: &[&str]) -> Result<(), Failure> {
    let value = text(object, field, field)?;
    one_of(value, allowed)
}

fn one_of(value: &str, allowed: &[&str]) -> Result<(), Failure> {
    if allowed.contains(&value) {
        Ok(())
    } else {
        Err(invalid("value is not in the supported enum"))
    }
}

fn positive_integer(object: &Map<String, Value>, field: &str) -> Result<f64, Failure> {
    let value = object
        .get(field)
        .and_then(Value::as_f64)
        .filter(|value| value.is_finite() && value.fract() == 0.0 && *value >= 1.0)
        .ok_or_else(|| invalid(&format!("{field} must be a positive integer")))?;
    Ok(value)
}

fn unique_identifier(
    object: &Map<String, Value>,
    field: &str,
    seen: &mut BTreeSet<String>,
) -> Result<(), Failure> {
    let value = text(object, field, field)?;
    identifier(value)?;
    if !seen.insert(value.to_owned()) {
        return Err(invalid(&format!(
            "Duplicate reconstruction coverage {field}"
        )));
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Timestamp {
    pub epoch_seconds: i128,
    pub fraction: String,
}

pub(crate) fn parse_timestamp(value: &str) -> Result<Timestamp, ()> {
    if !value.is_ascii() {
        return Err(());
    }

    let (date, time_and_zone) = value.split_once('T').ok_or(())?;
    if date.len() != 10 {
        return Err(());
    }
    let date_bytes = date.as_bytes();
    if date_bytes[4] != b'-'
        || date_bytes[7] != b'-'
        || date_bytes
            .iter()
            .enumerate()
            .any(|(index, byte)| !matches!(index, 4 | 7) && !byte.is_ascii_digit())
    {
        return Err(());
    }
    let year: i128 = date[0..4].parse().map_err(|_| ())?;
    let month: i128 = date[5..7].parse().map_err(|_| ())?;
    let day: i128 = date[8..10].parse().map_err(|_| ())?;
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => return Err(()),
    };
    if day < 1 || day > days_in_month {
        return Err(());
    }

    let (time, offset_seconds) = parse_time_and_offset(time_and_zone)?;
    let seconds = days_before_year(year)
        .checked_add(days_before_month(year, month))
        .and_then(|days| days.checked_add(day - 1))
        .and_then(|days| days.checked_sub(days_before_year(1970) + days_before_month(1970, 1)))
        .and_then(|days| days.checked_mul(86_400))
        .and_then(|seconds| seconds.checked_add(time))
        .and_then(|seconds| seconds.checked_sub(offset_seconds))
        .ok_or(())?;

    Ok(Timestamp {
        epoch_seconds: seconds,
        fraction: fractional_part(time_and_zone)?
            .trim_end_matches('0')
            .to_owned(),
    })
}

fn parse_time_and_offset(value: &str) -> Result<(i128, i128), ()> {
    let zone_index = value.rfind(['Z', '+', '-']).ok_or(())?;
    let (time, zone) = value.split_at(zone_index);
    let offset_seconds = if zone == "Z" {
        0
    } else {
        if zone.len() != 6 || zone.as_bytes().get(3) != Some(&b':') {
            return Err(());
        }
        let hour: i128 = zone[1..3].parse().map_err(|_| ())?;
        let minute: i128 = zone[4..6].parse().map_err(|_| ())?;
        if hour > 23 || minute > 59 {
            return Err(());
        }
        let sign = if zone.starts_with('-') { -1 } else { 1 };
        sign * (hour * 60 + minute) * 60
    };
    let (time_without_fraction, _fraction) = match time.split_once('.') {
        Some((base, fraction))
            if !fraction.is_empty() && fraction.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            (base, Some(fraction))
        }
        Some(_) => return Err(()),
        None => (time, None),
    };
    let segments: Vec<&str> = time_without_fraction.split(':').collect();
    if !(segments.len() == 2 || segments.len() == 3) {
        return Err(());
    }
    let hour: i128 = segments[0].parse().map_err(|_| ())?;
    let minute: i128 = segments[1].parse().map_err(|_| ())?;
    let second: i128 = if segments.len() == 3 {
        segments[2].parse().map_err(|_| ())?
    } else {
        0
    };
    if segments
        .iter()
        .any(|segment| segment.len() != 2 || !segment.bytes().all(|byte| byte.is_ascii_digit()))
        || (time.split_once('.').is_some() && segments.len() != 3)
        || segments[0].len() != 2
        || segments[1].len() != 2
        || (segments.len() == 3 && segments[2].len() != 2)
        || hour < 0
        || hour > 23
        || minute < 0
        || minute > 59
        || second < 0
        || second > 59
    {
        return Err(());
    }
    Ok((hour * 3600 + minute * 60 + second, offset_seconds))
}

fn fractional_part(value: &str) -> Result<&str, ()> {
    let time_end = value.rfind(['Z', '+', '-']).ok_or(())?;
    let time = &value[..time_end];
    match time.split_once('.') {
        Some((base, fraction))
            if base.matches(':').count() == 2
                && !fraction.is_empty()
                && fraction.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            Ok(fraction)
        }
        Some(_) => Err(()),
        None => Ok(""),
    }
}

fn days_before_year(year: i128) -> i128 {
    365 * year + (year + 3) / 4 - (year + 99) / 100 + (year + 399) / 400
}

fn days_before_month(year: i128, month: i128) -> i128 {
    (1..month)
        .map(|month| match month {
            2 if is_leap_year(year) => 29,
            2 => 28,
            4 | 6 | 9 | 11 => 30,
            _ => 31,
        })
        .sum()
}

fn is_leap_year(year: i128) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn strings<'a>(value: &'a Value, field: &str) -> Result<Vec<&'a str>, Failure> {
    value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(&format!("{field} must be an array")))?
        .iter()
        .map(|item| {
            item.as_str()
                .ok_or_else(|| invalid(&format!("{field} values must be strings")))
        })
        .collect()
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide a schema-valid reconstruction coverage snapshot with authenticated Evidence and a declared boundary.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_comparison_preserves_offsets_and_submillisecond_precision() {
        let later = parse_timestamp("2026-07-16T04:00:00.0009-05:00").expect("valid offset time");
        let earlier = parse_timestamp("2026-07-16T08:00:00.0008Z").expect("valid UTC time");
        assert!(compare_timestamps(&later, &earlier).is_gt());
    }

    #[test]
    fn timestamp_parser_rejects_invalid_calendar_and_offset_values() {
        assert!(parse_timestamp("2026-02-29T12:00Z").is_err());
        assert!(parse_timestamp("2026-07-16T12:00+24:00").is_err());
        assert!(parse_timestamp("2026-07-16T12:00").is_err());
        assert!(parse_timestamp("2026-07-16T12:00.1Z").is_err());
        assert!(parse_timestamp("2026-07-16T-1:00Z").is_err());
        assert!(parse_timestamp("２０２６-07-16T12:00Z").is_err());
    }

    #[test]
    fn timestamp_parser_anchors_the_unix_epoch() {
        let epoch = parse_timestamp("1970-01-01T00:00:00Z").expect("valid epoch");
        let before_epoch = parse_timestamp("1969-12-31T23:59:59.9Z").expect("valid time");
        assert_eq!(epoch.epoch_seconds, 0);
        assert!(compare_timestamps(&before_epoch, &epoch).is_lt());
    }
}

pub(crate) fn compare_timestamps(left: &Timestamp, right: &Timestamp) -> std::cmp::Ordering {
    left.epoch_seconds.cmp(&right.epoch_seconds).then_with(|| {
        let width = left.fraction.len().max(right.fraction.len());
        (0..width)
            .map(|index| {
                left.fraction
                    .as_bytes()
                    .get(index)
                    .copied()
                    .unwrap_or(b'0')
                    .cmp(
                        &right
                            .fraction
                            .as_bytes()
                            .get(index)
                            .copied()
                            .unwrap_or(b'0'),
                    )
            })
            .find(|ordering| !ordering.is_eq())
            .unwrap_or(std::cmp::Ordering::Equal)
    })
}
