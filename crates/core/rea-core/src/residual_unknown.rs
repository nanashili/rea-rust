//! Authenticated residual-unknown revisions and their complete Evidence graph.

use crate::{JsonText, canonical_json, evidence::record::EvidenceRecord};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::value::RawValue;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

/// One validated revision retains its full source record and immutable facts.
#[derive(Debug)]
pub struct ResidualUnknown {
    raw: Box<RawValue>,
    unknown_id: String,
    revision: u64,
    previous_revision_digest: Option<String>,
    revision_digest: String,
    status: String,
    severity: String,
    domain: JsonText,
    supporting_evidence_ids: Vec<String>,
    contradicting_evidence_ids: Vec<String>,
    required_authority: Option<String>,
    required_confidence: String,
    required_environment: Option<EnvironmentRequirement>,
    relationships: Vec<Relationship>,
    resolution: Option<Resolution>,
    mutation_evidence_ids: Vec<String>,
}

/// Validation or authentication failure for one residual-unknown revision.
#[derive(Debug)]
pub enum ResidualUnknownError {
    /// The strict record shape or its field constraints were invalid.
    Invalid(String),
    /// Canonical JSON could not represent the admitted source value.
    Canonical(canonical_json::Error),
    /// A temporary JSON representation could not be encoded.
    Encoding(serde_json::Error),
}

impl fmt::Display for ResidualUnknownError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => formatter.write_str(message),
            Self::Canonical(error) => error.fmt(formatter),
            Self::Encoding(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for ResidualUnknownError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Canonical(error) => Some(error),
            Self::Encoding(error) => Some(error),
            Self::Invalid(_) => None,
        }
    }
}

impl ResidualUnknown {
    /// Parse a strict revision and authenticate immutable identity and revision digest.
    pub fn parse(input: &RawValue) -> Result<Self, ResidualUnknownError> {
        let shape: UnknownShape<'_> = serde_json::from_str(input.get())
            .map_err(|error| ResidualUnknownError::Invalid(error.to_string()))?;
        let source_fields = object_fields(input)?;

        validate_prefixed_digest(&shape.unknown_id, "unk_")?;
        if shape.revision == 0 || shape.revision > 9_007_199_254_740_991 {
            return invalid("Residual unknown revision is outside the supported integer range");
        }

        let previous_revision_digest = nullable_digest(shape.previous_revision_digest)?;
        if (shape.revision == 1) != previous_revision_digest.is_none() {
            return invalid("Only the first residual unknown revision has no predecessor");
        }
        let revision_digest = parse_digest(shape.revision_digest, "revision_digest")?;
        nullable_digest(shape.scope_digest)?;

        validate_trimmed_text(&shape.question, "question")?;
        validate_trimmed_text(&shape.domain, "domain")?;
        validate_enum(
            &shape.status,
            &[
                "open",
                "investigating",
                "blocked",
                "contradicted",
                "resolved",
            ],
            "status",
        )?;
        validate_enum(
            &shape.severity,
            &["low", "medium", "high", "critical"],
            "severity",
        )?;

        let comparison_scope = parse_comparison_scope(shape.comparison_conclusion_scope)?;
        let supporting_evidence_ids = parse_evidence_ids(
            shape.supporting_evidence_ids,
            "supporting_evidence_ids",
            false,
        )?;
        let contradicting_evidence_ids = parse_evidence_ids(
            shape.contradicting_evidence_ids,
            "contradicting_evidence_ids",
            false,
        )?;
        let mutation_evidence_ids =
            parse_evidence_ids(shape.mutation_evidence_ids, "mutation_evidence_ids", true)?;
        let required_authority = nullable_enum(
            shape.required_authority,
            &[
                "shipped-artifact",
                "controlled-replay",
                "historical-reference",
                "external-service",
                "analyst-inference",
            ],
            "required_authority",
        )?;
        let required_confidence = parse_string(shape.required_confidence, "required_confidence")?;
        validate_enum(
            &required_confidence,
            &["observed", "derived", "inferred"],
            "required_confidence",
        )?;
        let required_environment = parse_environment(shape.required_environment)?;
        parse_probes(shape.recommended_probes)?;
        let relationships = parse_relationships(shape.relationships, &shape.unknown_id)?;
        let resolution = parse_resolution(shape.resolution)?;

        validate_revision_state(
            &shape.status,
            &contradicting_evidence_ids,
            resolution.as_ref(),
            &supporting_evidence_ids,
            &comparison_scope,
            shape.domain.as_str() == Some("function-comparison"),
        )?;
        validate_unique_ids(&supporting_evidence_ids, "supporting_evidence_ids")?;
        validate_unique_ids(&contradicting_evidence_ids, "contradicting_evidence_ids")?;
        validate_unique_ids(&mutation_evidence_ids, "mutation_evidence_ids")?;
        validate_disjoint_evidence(&supporting_evidence_ids, &contradicting_evidence_ids)?;
        validate_unique_relationships(&relationships)?;

        let normalized_question = normalized_question_raw(&shape.question)?;
        let expected_id = stable_id(
            &source_fields,
            shape.comparison_conclusion_scope.is_some(),
            normalized_question,
        )?;
        if shape.unknown_id != expected_id {
            return invalid("Residual unknown ID does not match its immutable identity");
        }

        let calculated_revision_digest = compute_revision_digest(&source_fields)?;
        if revision_digest != calculated_revision_digest {
            return invalid("Residual unknown revision digest does not match");
        }

        let raw = canonical_raw(input)?;
        Ok(Self {
            raw,
            unknown_id: shape.unknown_id,
            revision: shape.revision,
            previous_revision_digest,
            revision_digest,
            status: shape.status,
            severity: shape.severity,
            domain: shape.domain,
            supporting_evidence_ids,
            contradicting_evidence_ids,
            required_authority,
            required_confidence,
            required_environment,
            relationships,
            resolution,
            mutation_evidence_ids,
        })
    }

    /// Complete authenticated source revision.
    pub fn raw(&self) -> &RawValue {
        &self.raw
    }

    /// Immutable unknown identity.
    pub fn unknown_id(&self) -> &str {
        &self.unknown_id
    }

    /// One-based revision number.
    pub fn revision(&self) -> u64 {
        self.revision
    }

    /// Revision-chain predecessor digest, absent only for revision one.
    pub fn previous_revision_digest(&self) -> Option<&str> {
        self.previous_revision_digest.as_deref()
    }

    /// Authenticated digest for this revision.
    pub fn revision_digest(&self) -> &str {
        &self.revision_digest
    }

    /// Evidence referenced by this revision, including its resolution evidence.
    pub fn referenced_evidence_ids(&self) -> impl Iterator<Item = &str> {
        self.supporting_evidence_ids
            .iter()
            .map(String::as_str)
            .chain(self.contradicting_evidence_ids.iter().map(String::as_str))
            .chain(self.mutation_evidence_ids.iter().map(String::as_str))
            .chain(
                self.resolution
                    .iter()
                    .flat_map(|resolution| resolution.evidence_ids.iter().map(String::as_str)),
            )
    }

    /// Current lifecycle status of this revision.
    pub fn status(&self) -> &str {
        &self.status
    }

    /// Current severity of this revision.
    pub fn severity(&self) -> &str {
        &self.severity
    }

    /// Match the exact domain text using its retained UTF-16 code units.
    pub fn domain_matches(&self, candidate: &str) -> bool {
        self.domain
            .utf16_units()
            .is_ok_and(|units| units == candidate.encode_utf16().collect::<Vec<_>>())
    }

    /// Whether this revision carries a verified truth disposition.
    pub fn truth_verified(&self) -> bool {
        self.resolution
            .as_ref()
            .is_some_and(|resolution| resolution.disposition == "verified")
    }
}

impl Serialize for ResidualUnknown {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.raw.serialize(serializer)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UnknownShape<'a> {
    unknown_id: String,
    revision: u64,
    #[serde(borrow)]
    previous_revision_digest: &'a RawValue,
    #[serde(borrow)]
    revision_digest: &'a RawValue,
    #[serde(borrow)]
    scope_digest: &'a RawValue,
    question: JsonText,
    status: String,
    severity: String,
    domain: JsonText,
    #[serde(default, borrow)]
    comparison_conclusion_scope: Option<&'a RawValue>,
    #[serde(borrow)]
    supporting_evidence_ids: &'a RawValue,
    #[serde(borrow)]
    contradicting_evidence_ids: &'a RawValue,
    #[serde(borrow)]
    required_authority: &'a RawValue,
    #[serde(borrow)]
    required_confidence: &'a RawValue,
    #[serde(borrow)]
    required_environment: &'a RawValue,
    #[serde(borrow)]
    recommended_probes: &'a RawValue,
    #[serde(borrow)]
    relationships: &'a RawValue,
    #[serde(borrow)]
    resolution: &'a RawValue,
    #[serde(borrow)]
    mutation_evidence_ids: &'a RawValue,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ComparisonScope {
    comparison_evidence_id: String,
    dimensions: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Probe {
    operation: JsonText,
    rationale: JsonText,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Relationship {
    #[serde(rename = "type")]
    kind: String,
    unknown_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Resolution {
    disposition: String,
    rationale: JsonText,
    evidence_ids: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvironmentShape {
    id: Box<RawValue>,
    platform: Box<RawValue>,
    architecture: Box<RawValue>,
    isolation: Box<RawValue>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceEnvironment {
    id: JsonText,
    platform: JsonText,
    architecture: JsonText,
    isolation: JsonText,
}

#[derive(Debug)]
struct EnvironmentRequirement {
    id: Option<JsonText>,
    platform: Option<JsonText>,
    architecture: Option<JsonText>,
    isolation: Option<JsonText>,
}

/// Validate complete histories, Evidence references, resolutions and dependencies.
pub fn validate_histories<'unknown, 'evidence>(
    unknowns: impl IntoIterator<Item = &'unknown ResidualUnknown>,
    records: impl IntoIterator<Item = &'evidence EvidenceRecord>,
) -> Result<(), ResidualUnknownError> {
    let unknowns = unknowns.into_iter().collect::<Vec<_>>();
    let evidence_by_id = records
        .into_iter()
        .map(|record| (record.evidence_id(), record))
        .collect::<BTreeMap<_, _>>();
    let mut heads = BTreeMap::<&str, &ResidualUnknown>::new();
    let mut previous: Option<(&str, u64)> = None;

    for unknown in &unknowns {
        let current_key = (unknown.unknown_id(), unknown.revision());
        if previous.is_some_and(|value| current_key <= value) {
            return invalid("Residual unknown revisions are not in canonical order");
        }
        previous = Some(current_key);

        if let Some(head) = heads.get(unknown.unknown_id()) {
            if unknown.revision() != head.revision() + 1
                || unknown.previous_revision_digest() != Some(head.revision_digest())
            {
                return invalid(format!(
                    "Residual unknown {} revision history has a gap or broken chain",
                    unknown.unknown_id()
                ));
            }
        } else if unknown.revision() != 1 || unknown.previous_revision_digest().is_some() {
            return invalid(format!(
                "Residual unknown {} revision history does not start at one",
                unknown.unknown_id()
            ));
        }
        heads.insert(unknown.unknown_id(), unknown);
    }

    for unknown in &unknowns {
        validate_evidence_references(unknown, &evidence_by_id)?;
        validate_unknown_references(unknown, &heads)?;
        if let Some(resolution) = &unknown.resolution
            && resolution.disposition == "verified"
        {
            validate_verified_resolution(unknown, resolution, &evidence_by_id)?;
        }
    }

    reject_dependency_cycles(&heads)
}

fn parse_comparison_scope(
    raw: Option<&RawValue>,
) -> Result<Option<ComparisonScope>, ResidualUnknownError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    if raw.get() == "null" {
        return invalid("Comparison conclusion scope must be omitted or an object");
    }
    let scope: ComparisonScope = decode(raw, "comparison_conclusion_scope")?;
    validate_prefixed_digest(&scope.comparison_evidence_id, "ev_")?;
    const DIMENSIONS: &[&str] = &[
        "overall",
        "identity",
        "pseudocode",
        "assembly",
        "comments",
        "calls",
        "references",
        "strings_names",
        "cfg",
    ];
    if scope.dimensions.is_empty()
        || scope
            .dimensions
            .iter()
            .any(|dimension| !DIMENSIONS.contains(&dimension.as_str()))
        || scope.dimensions.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return invalid("Comparison dimensions must be sorted, unique and supported");
    }
    Ok(Some(scope))
}

fn parse_environment(
    raw: &RawValue,
) -> Result<Option<EnvironmentRequirement>, ResidualUnknownError> {
    if raw.get() == "null" {
        return Ok(None);
    }
    let shape: EnvironmentShape = decode(raw, "required_environment")?;
    let id = nullable_text(&shape.id, "required_environment.id")?;
    let platform = nullable_text(&shape.platform, "required_environment.platform")?;
    let architecture = nullable_text(&shape.architecture, "required_environment.architecture")?;
    let isolation = nullable_text(&shape.isolation, "required_environment.isolation")?;

    if let Some(value) = &isolation {
        let allowed = ["none", "process", "container", "virtual-machine"];
        if !allowed
            .iter()
            .any(|candidate| value.as_str() == Some(*candidate))
        {
            return invalid("required_environment.isolation is unsupported");
        }
    }

    Ok(Some(EnvironmentRequirement {
        id,
        platform,
        architecture,
        isolation,
    }))
}

fn parse_probes(raw: &RawValue) -> Result<(), ResidualUnknownError> {
    let probes: Vec<Probe> = decode(raw, "recommended_probes")?;
    for probe in &probes {
        validate_nonempty_text(&probe.operation, "recommended_probes.operation")?;
        validate_trimmed_text(&probe.rationale, "recommended_probes.rationale")?;
    }
    Ok(())
}

fn parse_relationships(
    raw: &RawValue,
    unknown_id: &str,
) -> Result<Vec<Relationship>, ResidualUnknownError> {
    let relationships: Vec<Relationship> = decode(raw, "relationships")?;
    for relationship in &relationships {
        validate_enum(
            &relationship.kind,
            &["depends-on", "related-to", "contradicts"],
            "relationships.type",
        )?;
        validate_prefixed_digest(&relationship.unknown_id, "unk_")?;
        if relationship.unknown_id == unknown_id {
            return invalid("A residual unknown cannot relate to itself");
        }
    }
    Ok(relationships)
}

fn parse_resolution(raw: &RawValue) -> Result<Option<Resolution>, ResidualUnknownError> {
    if raw.get() == "null" {
        return Ok(None);
    }
    let resolution: Resolution = decode(raw, "resolution")?;
    validate_enum(
        &resolution.disposition,
        &["verified", "withdrawn", "out-of-scope"],
        "resolution.disposition",
    )?;
    validate_trimmed_text(&resolution.rationale, "resolution.rationale")?;
    for evidence_id in &resolution.evidence_ids {
        validate_prefixed_digest(evidence_id, "ev_")?;
    }
    if resolution.disposition == "verified" && resolution.evidence_ids.is_empty() {
        return invalid("Verified resolution requires at least one Evidence ID");
    }
    Ok(Some(resolution))
}

fn validate_revision_state(
    status: &str,
    contradicting_evidence_ids: &[String],
    resolution: Option<&Resolution>,
    supporting_evidence_ids: &[String],
    comparison_scope: &Option<ComparisonScope>,
    is_function_comparison: bool,
) -> Result<(), ResidualUnknownError> {
    if (status == "resolved") != resolution.is_some() {
        return invalid("Only resolved residual unknowns carry a resolution");
    }
    if status == "contradicted" && contradicting_evidence_ids.is_empty() {
        return invalid("Contradicted status requires contradicting Evidence");
    }
    if let Some(scope) = comparison_scope {
        if !supporting_evidence_ids.contains(&scope.comparison_evidence_id)
            && !contradicting_evidence_ids.contains(&scope.comparison_evidence_id)
        {
            return invalid("Scoped comparison Evidence must support or contradict the unknown");
        }
        if !is_function_comparison {
            return invalid("Comparison conclusion scope requires function-comparison domain");
        }
    }
    Ok(())
}

fn validate_evidence_references(
    unknown: &ResidualUnknown,
    evidence_by_id: &BTreeMap<&str, &EvidenceRecord>,
) -> Result<(), ResidualUnknownError> {
    let mut referenced = unknown.supporting_evidence_ids.clone();
    referenced.extend(unknown.contradicting_evidence_ids.iter().cloned());
    referenced.extend(unknown.mutation_evidence_ids.iter().cloned());
    if let Some(resolution) = &unknown.resolution {
        referenced.extend(resolution.evidence_ids.iter().cloned());
    }

    for evidence_id in referenced {
        if !evidence_by_id.contains_key(evidence_id.as_str()) {
            return invalid(format!(
                "Residual unknown references missing Evidence {evidence_id}"
            ));
        }
    }
    Ok(())
}

fn validate_unknown_references(
    unknown: &ResidualUnknown,
    heads: &BTreeMap<&str, &ResidualUnknown>,
) -> Result<(), ResidualUnknownError> {
    for relationship in &unknown.relationships {
        if !heads.contains_key(relationship.unknown_id.as_str()) {
            return invalid(format!(
                "Residual unknown references missing unknown {}",
                relationship.unknown_id
            ));
        }
    }
    Ok(())
}

fn validate_verified_resolution(
    unknown: &ResidualUnknown,
    resolution: &Resolution,
    evidence_by_id: &BTreeMap<&str, &EvidenceRecord>,
) -> Result<(), ResidualUnknownError> {
    if !unknown.contradicting_evidence_ids.is_empty() {
        return invalid("Verified resolution cannot retain contradicting Evidence");
    }

    let qualifies = resolution.evidence_ids.iter().any(|evidence_id| {
        if !unknown.supporting_evidence_ids.contains(evidence_id) {
            return false;
        }
        let Some(evidence) = evidence_by_id.get(evidence_id.as_str()) else {
            return false;
        };
        if evidence.predicate_type().get() == "\"rea.residual-unknown-mutation\"" {
            return false;
        }
        evidence_qualifies(unknown, evidence)
    });

    if !qualifies {
        return invalid(format!(
            "Residual unknown {} has no qualifying resolution Evidence",
            unknown.unknown_id
        ));
    }
    Ok(())
}

fn evidence_qualifies(unknown: &ResidualUnknown, evidence: &EvidenceRecord) -> bool {
    if let Some(required) = &unknown.required_authority {
        let expected = serde_json::to_string(required).unwrap_or_default();
        if evidence.authority().get() != expected {
            return false;
        }
    }

    let Some(required_rank) = confidence_rank(&unknown.required_confidence) else {
        return false;
    };
    let actual_confidence = serde_json::from_str::<String>(evidence.confidence().get()).ok();
    let actual_rank = actual_confidence.as_deref().and_then(confidence_rank);
    if actual_rank.is_none_or(|actual_rank| actual_rank < required_rank) {
        return false;
    }

    let Some(requirement) = &unknown.required_environment else {
        return true;
    };
    let Some(manifest) = evidence.environment_manifest() else {
        return false;
    };
    let Ok(environment) = serde_json::from_str::<EvidenceEnvironment>(manifest.get()) else {
        return false;
    };
    requirement_matches(requirement, &environment)
}

fn requirement_matches(
    requirement: &EnvironmentRequirement,
    environment: &EvidenceEnvironment,
) -> bool {
    text_matches(&requirement.id, &environment.id)
        && text_matches(&requirement.platform, &environment.platform)
        && text_matches(&requirement.architecture, &environment.architecture)
        && text_matches(&requirement.isolation, &environment.isolation)
}

fn text_matches(requirement: &Option<JsonText>, actual: &JsonText) -> bool {
    requirement
        .as_ref()
        .is_none_or(|required| required.utf16_units().ok() == actual.utf16_units().ok())
}

fn reject_dependency_cycles(
    heads: &BTreeMap<&str, &ResidualUnknown>,
) -> Result<(), ResidualUnknownError> {
    struct Frame<'a> {
        unknown_id: &'a str,
        relationships: &'a [Relationship],
        next_relationship: usize,
    }

    let mut visited = BTreeSet::new();
    let mut active = BTreeSet::new();

    for root in heads.keys().copied() {
        if visited.contains(root) {
            continue;
        }
        let root_unknown = heads.get(root).copied().ok_or_else(|| {
            ResidualUnknownError::Invalid("Unknown dependency graph is inconsistent".into())
        })?;
        let mut pending = vec![Frame {
            unknown_id: root,
            relationships: &root_unknown.relationships,
            next_relationship: 0,
        }];
        active.insert(root);

        while !pending.is_empty() {
            let dependency = {
                let frame = pending.last_mut().expect("pending frame exists");
                let mut next_dependency = None;
                while frame.next_relationship < frame.relationships.len() {
                    let relationship = &frame.relationships[frame.next_relationship];
                    frame.next_relationship += 1;
                    if relationship.kind == "depends-on" {
                        next_dependency = Some(relationship.unknown_id.as_str());
                        break;
                    }
                }
                next_dependency
            };

            let Some(dependency) = dependency else {
                let completed = pending.pop().expect("pending frame exists");
                active.remove(completed.unknown_id);
                visited.insert(completed.unknown_id);
                continue;
            };

            if active.contains(dependency) {
                return invalid("Residual unknown dependency graph contains a cycle");
            }
            if visited.contains(dependency) {
                continue;
            }
            let unknown = heads.get(dependency).copied().ok_or_else(|| {
                ResidualUnknownError::Invalid("Unknown dependency graph is inconsistent".into())
            })?;
            active.insert(dependency);
            pending.push(Frame {
                unknown_id: dependency,
                relationships: &unknown.relationships,
                next_relationship: 0,
            });
        }
    }
    Ok(())
}

fn stable_id(
    fields: &BTreeMap<String, Box<RawValue>>,
    has_comparison_scope: bool,
    normalized_question: Box<RawValue>,
) -> Result<String, ResidualUnknownError> {
    let mut selected = BTreeMap::new();
    for name in ["domain", "scope_digest"] {
        selected.insert(name.to_owned(), copy_field(fields, name)?);
    }
    selected.insert("question".to_owned(), normalized_question);
    if has_comparison_scope {
        selected.insert(
            "comparison_conclusion_scope".into(),
            copy_field(fields, "comparison_conclusion_scope")?,
        );
    }
    let projection =
        serde_json::value::to_raw_value(&selected).map_err(ResidualUnknownError::Encoding)?;
    let digest =
        canonical_json::digest_raw(&projection).map_err(ResidualUnknownError::Canonical)?;
    Ok(format!("unk_{digest}"))
}

fn normalized_question_raw(question: &JsonText) -> Result<Box<RawValue>, ResidualUnknownError> {
    let units = question
        .utf16_units()
        .map_err(|error| ResidualUnknownError::Invalid(error.to_string()))?;
    let first = units
        .iter()
        .position(|unit| !is_js_whitespace(*unit))
        .unwrap_or(units.len());
    let last = units
        .iter()
        .rposition(|unit| !is_js_whitespace(*unit))
        .map_or(first, |index| index + 1);

    let mut normalized = Vec::with_capacity(last.saturating_sub(first));
    let mut previous_was_whitespace = false;
    for unit in &units[first..last] {
        if is_js_whitespace(*unit) {
            if !previous_was_whitespace {
                normalized.push(u16::from(b' '));
            }
            previous_was_whitespace = true;
            continue;
        }
        normalized.push(*unit);
        previous_was_whitespace = false;
    }

    let mut json = String::with_capacity(normalized.len() + 2);
    json.push('"');
    for unit in normalized {
        append_json_utf16_unit(&mut json, unit);
    }
    json.push('"');
    RawValue::from_string(json).map_err(ResidualUnknownError::Encoding)
}

fn append_json_utf16_unit(json: &mut String, unit: u16) {
    match unit {
        0x0022 => json.push_str("\\\""),
        0x005c => json.push_str("\\\\"),
        0x0008 => json.push_str("\\b"),
        0x0009 => json.push_str("\\t"),
        0x000a => json.push_str("\\n"),
        0x000c => json.push_str("\\f"),
        0x000d => json.push_str("\\r"),
        0x0000..=0x001f | 0x007f..=0xffff => {
            json.push_str("\\u");
            const HEX: &[u8; 16] = b"0123456789abcdef";
            for shift in [12, 8, 4, 0] {
                json.push(char::from(HEX[usize::from((unit >> shift) & 15)]));
            }
        }
        0x0020..=0x007e => json.push(char::from(unit as u8)),
    }
}

fn compute_revision_digest(
    fields: &BTreeMap<String, Box<RawValue>>,
) -> Result<String, ResidualUnknownError> {
    let mut semantic = fields.clone();
    semantic.remove("revision_digest");
    let projection =
        serde_json::value::to_raw_value(&semantic).map_err(ResidualUnknownError::Encoding)?;
    canonical_json::digest_raw(&projection).map_err(ResidualUnknownError::Canonical)
}

fn object_fields(
    input: &RawValue,
) -> Result<BTreeMap<String, Box<RawValue>>, ResidualUnknownError> {
    serde_json::from_str(input.get())
        .map_err(|error| ResidualUnknownError::Invalid(error.to_string()))
}

fn canonical_raw(input: &RawValue) -> Result<Box<RawValue>, ResidualUnknownError> {
    let fields = object_fields(input)?;
    serde_json::value::to_raw_value(&fields).map_err(ResidualUnknownError::Encoding)
}

fn copy_field(
    fields: &BTreeMap<String, Box<RawValue>>,
    name: &'static str,
) -> Result<Box<RawValue>, ResidualUnknownError> {
    fields
        .get(name)
        .map(|value| RawValue::from_string(value.get().to_owned()))
        .transpose()
        .map_err(ResidualUnknownError::Encoding)?
        .ok_or_else(|| {
            ResidualUnknownError::Invalid(format!("Missing residual unknown field {name}"))
        })
}

fn parse_evidence_ids(
    raw: &RawValue,
    field: &'static str,
    require_one: bool,
) -> Result<Vec<String>, ResidualUnknownError> {
    let values: Vec<String> = decode(raw, field)?;
    if require_one && values.is_empty() {
        return invalid(format!("{field} must contain at least one Evidence ID"));
    }
    for value in &values {
        validate_prefixed_digest(value, "ev_")?;
    }
    Ok(values)
}

fn validate_unique_ids(values: &[String], field: &'static str) -> Result<(), ResidualUnknownError> {
    if values.iter().collect::<BTreeSet<_>>().len() != values.len() {
        return invalid(format!("{field} must contain unique Evidence IDs"));
    }
    Ok(())
}

fn validate_disjoint_evidence(
    supporting: &[String],
    contradicting: &[String],
) -> Result<(), ResidualUnknownError> {
    let contradicting = contradicting.iter().collect::<BTreeSet<_>>();
    if supporting.iter().any(|value| contradicting.contains(value)) {
        return invalid("Evidence cannot simultaneously support and contradict");
    }
    Ok(())
}

fn validate_unique_relationships(
    relationships: &[Relationship],
) -> Result<(), ResidualUnknownError> {
    let keys = relationships
        .iter()
        .map(|relationship| (relationship.kind.as_str(), relationship.unknown_id.as_str()))
        .collect::<BTreeSet<_>>();
    if keys.len() != relationships.len() {
        return invalid("Residual unknown relationships must be unique");
    }
    Ok(())
}

fn nullable_digest(raw: &RawValue) -> Result<Option<String>, ResidualUnknownError> {
    if raw.get() == "null" {
        return Ok(None);
    }
    Ok(Some(parse_digest(raw, "digest")?))
}

fn nullable_enum(
    raw: &RawValue,
    allowed: &[&str],
    field: &'static str,
) -> Result<Option<String>, ResidualUnknownError> {
    if raw.get() == "null" {
        return Ok(None);
    }
    let value = parse_string(raw, field)?;
    validate_enum(&value, allowed, field)?;
    Ok(Some(value))
}

fn nullable_text(
    raw: &RawValue,
    field: &'static str,
) -> Result<Option<JsonText>, ResidualUnknownError> {
    if raw.get() == "null" {
        return Ok(None);
    }
    let value: JsonText = decode(raw, field)?;
    validate_nonempty_text(&value, field)?;
    Ok(Some(value))
}

fn parse_digest(raw: &RawValue, field: &'static str) -> Result<String, ResidualUnknownError> {
    let value = parse_string(raw, field)?;
    validate_hex_digest(&value, field)?;
    Ok(value)
}

fn parse_string(raw: &RawValue, field: &'static str) -> Result<String, ResidualUnknownError> {
    decode(raw, field)
}

fn validate_prefixed_digest(value: &str, prefix: &str) -> Result<(), ResidualUnknownError> {
    let Some(digest) = value.strip_prefix(prefix) else {
        return invalid(format!("Identifier must begin with {prefix}"));
    };
    validate_hex_digest(digest, "identifier")
}

fn validate_hex_digest(value: &str, field: &'static str) -> Result<(), ResidualUnknownError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return invalid(format!("{field} must be a lower-case SHA-256 digest"));
    }
    Ok(())
}

fn validate_nonempty_text(
    value: &JsonText,
    field: &'static str,
) -> Result<(), ResidualUnknownError> {
    if value
        .utf16_units()
        .map_err(|error| ResidualUnknownError::Invalid(error.to_string()))?
        .is_empty()
    {
        return invalid(format!("{field} must be nonempty"));
    }
    Ok(())
}

fn validate_trimmed_text(
    value: &JsonText,
    field: &'static str,
) -> Result<(), ResidualUnknownError> {
    let units = value
        .utf16_units()
        .map_err(|error| ResidualUnknownError::Invalid(error.to_string()))?;
    if units.is_empty() || is_js_whitespace(units[0]) || is_js_whitespace(*units.last().unwrap()) {
        return invalid(format!("{field} must be nonempty and trimmed"));
    }
    Ok(())
}

fn is_js_whitespace(unit: u16) -> bool {
    matches!(
        unit,
        0x0009..=0x000d
            | 0x0020
            | 0x00a0
            | 0x1680
            | 0x2000..=0x200a
            | 0x2028..=0x2029
            | 0x202f
            | 0x205f
            | 0x3000
            | 0xfeff
    )
}

fn validate_enum(
    value: &str,
    allowed: &[&str],
    field: &'static str,
) -> Result<(), ResidualUnknownError> {
    if !allowed.contains(&value) {
        return invalid(format!("{field} is unsupported"));
    }
    Ok(())
}

fn confidence_rank(value: &str) -> Option<u8> {
    match value {
        "inferred" => Some(1),
        "derived" => Some(2),
        "observed" => Some(3),
        _ => None,
    }
}

fn decode<T: DeserializeOwned>(
    raw: &RawValue,
    field: &'static str,
) -> Result<T, ResidualUnknownError> {
    serde_json::from_str(raw.get())
        .map_err(|error| ResidualUnknownError::Invalid(format!("{field}: {error}")))
}

fn invalid<T>(message: impl Into<String>) -> Result<T, ResidualUnknownError> {
    Err(ResidualUnknownError::Invalid(message.into()))
}
