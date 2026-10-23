//! Provider-neutral authenticated Evidence records.
//!
//! Source metadata and JSON payloads remain lossless raw values. This owner
//! validates the public envelope and authenticates semantic identity without
//! assigning provider-specific meaning to normalized results.

use crate::{JsonText, canonical_json, evidence::is_sha256};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use std::{collections::BTreeMap, fmt};

/// A validated record retains its complete JSON representation and identity.
#[derive(Debug)]
pub struct EvidenceRecord {
    raw: Box<RawValue>,
    evidence_id: String,
    subject_sha256: Option<String>,
    subject: Box<RawValue>,
    artifact_manifest: Option<Box<RawValue>>,
    provider_manifest: Box<RawValue>,
    environment_manifest: Option<Box<RawValue>>,
    operation: Box<RawValue>,
    predicate_type: Box<RawValue>,
    confidence: Box<RawValue>,
    authority: Box<RawValue>,
    scenario_manifest: Option<Box<RawValue>>,
    capture_manifest: Option<Box<RawValue>>,
    limitation_count: usize,
    analysis_profile_digest: Option<String>,
}

/// Evidence envelope validation or semantic authentication failed.
#[derive(Debug)]
pub enum EvidenceRecordError {
    /// Canonical JSON could not preserve or authenticate the input.
    Canonical(canonical_json::Error),
    /// The input did not satisfy the strict Evidence schema.
    Invalid(String),
    /// The supplied identifier does not commit to the supplied semantic data.
    SemanticIdMismatch,
    /// The normalized or raw payload exceeds the supported JSON representation.
    Json(serde_json::Error),
}

impl fmt::Display for EvidenceRecordError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Canonical(error) => error.fmt(formatter),
            Self::Invalid(message) => formatter.write_str(message),
            Self::SemanticIdMismatch => {
                formatter.write_str("Evidence semantic identifier does not match its record")
            }
            Self::Json(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for EvidenceRecordError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Canonical(error) => Some(error),
            Self::Json(error) => Some(error),
            Self::Invalid(_) | Self::SemanticIdMismatch => None,
        }
    }
}

impl EvidenceRecord {
    /// Create an authenticated Evidence record from its unsigned JSON object.
    ///
    /// The input must contain every standard Evidence field except
    /// `evidence_id`. The generated identifier uses the same semantic
    /// projection as `parse`, then the completed record is validated again.
    ///
    /// # Errors
    /// Invalid envelopes, unsupported JSON values, and canonicalization
    /// failures are returned without producing a record.
    pub fn create_unsigned(input: &RawValue) -> Result<Self, EvidenceRecordError> {
        let mut fields: BTreeMap<String, Box<RawValue>> = decode(input)?;
        if fields.contains_key("evidence_id") {
            return invalid("Unsigned Evidence input must omit evidence_id");
        }

        let placeholder = format!("ev_{}", "0".repeat(64));
        fields.insert(
            "evidence_id".into(),
            serde_json::value::to_raw_value(&placeholder).map_err(EvidenceRecordError::Json)?,
        );
        let provisional =
            serde_json::value::to_raw_value(&fields).map_err(EvidenceRecordError::Json)?;
        let shape: RecordShape<'_> = decode(&provisional)?;
        let (_, subject) = parse_subject(shape.subject)?;
        let semantic = semantic_projection(&shape, subject.as_ref())?;
        let digest =
            canonical_json::digest_raw(&semantic).map_err(EvidenceRecordError::Canonical)?;

        fields.insert(
            "evidence_id".into(),
            serde_json::value::to_raw_value(&format!("ev_{digest}"))
                .map_err(EvidenceRecordError::Json)?,
        );
        let completed =
            serde_json::value::to_raw_value(&fields).map_err(EvidenceRecordError::Json)?;
        Self::parse(&completed)
    }

    /// Parse a strict Evidence record and verify its provider-neutral identity.
    ///
    /// Input object keys are normalized using ECMAScript JSON semantics, which
    /// includes UTF-16 key ordering and last-key-wins duplicate handling.
    ///
    /// # Errors
    /// Invalid schema values, unsupported JSON numbers/depth, and mismatched
    /// semantic identifiers are rejected without changing source values.
    pub fn parse(input: &RawValue) -> Result<Self, EvidenceRecordError> {
        let raw = canonicalize(input)?;
        let shape: RecordShape = decode(&raw)?;

        validate_prefixed_digest(&shape.evidence_id, "ev_")?;
        let (subject_sha256, subject_semantic) = parse_subject(shape.subject)?;
        let provider = parse_provider(shape.provider, false)?;
        let profile_digest = parse_profile(shape.analysis_profile, &provider)?;
        validate_text(shape.predicate_type, "predicate_type")?;
        validate_text(shape.operation, "operation")?;
        require_object(shape.parameters, "parameters")?;
        validate_json(shape.raw_result)?;
        validate_json(shape.normalized_result)?;
        validate_enum(
            shape.confidence,
            &["observed", "derived", "inferred"],
            "confidence",
        )?;
        validate_enum(
            shape.authority,
            &[
                "shipped-artifact",
                "controlled-replay",
                "historical-reference",
                "external-service",
                "analyst-inference",
            ],
            "authority",
        )?;
        parse_environment(shape.environment)?;
        validate_string_array(shape.limitations)?;
        validate_relationship_coverage(shape.relationship_coverage)?;
        validate_locations(shape.locations)?;
        validate_evidence_links(shape.evidence_links)?;

        let subject = copy_raw(shape.subject)?;
        let artifact_manifest = match &subject_semantic {
            Some(subject) => Some(
                serde_json::value::to_raw_value(&ArtifactManifest {
                    digest: subject.digest,
                    format: &subject.format,
                    architecture: subject.architecture,
                })
                .map_err(EvidenceRecordError::Json)?,
            ),
            None => None,
        };
        let provider_manifest =
            serde_json::value::to_raw_value(&provider).map_err(EvidenceRecordError::Json)?;
        let environment_manifest = if is_null(shape.environment) {
            None
        } else {
            let environment: EnvironmentShape = decode(shape.environment)?;
            Some(serde_json::value::to_raw_value(&environment).map_err(EvidenceRecordError::Json)?)
        };
        let confidence = copy_raw(shape.confidence)?;
        let authority = copy_raw(shape.authority)?;
        let scenario_manifest = (shape.authority.get() == "\"controlled-replay\"")
            .then(|| {
                serde_json::value::to_raw_value(&ScenarioManifest {
                    evidence_id: &shape.evidence_id,
                    operation: shape.operation,
                    authority: shape.authority,
                })
            })
            .transpose()
            .map_err(EvidenceRecordError::Json)?;
        let capture_manifest = (shape.predicate_type.get() == "\"rea.process-capture\"")
            .then(|| {
                serde_json::value::to_raw_value(&CaptureManifest {
                    evidence_id: &shape.evidence_id,
                    predicate_type: shape.predicate_type,
                })
            })
            .transpose()
            .map_err(EvidenceRecordError::Json)?;
        let limitation_count = decode::<Vec<&RawValue>>(shape.limitations)?.len();

        let semantic = semantic_projection(&shape, subject_semantic.as_ref())?;
        let calculated = format!(
            "ev_{}",
            canonical_json::digest_raw(&semantic).map_err(EvidenceRecordError::Canonical,)?
        );
        if calculated != shape.evidence_id {
            return Err(EvidenceRecordError::SemanticIdMismatch);
        }

        let evidence_id = shape.evidence_id.clone();
        let operation = copy_raw(shape.operation)?;
        let predicate_type = copy_raw(shape.predicate_type)?;
        drop(shape);

        Ok(Self {
            raw,
            evidence_id,
            subject_sha256,
            subject,
            artifact_manifest,
            provider_manifest,
            environment_manifest,
            operation,
            predicate_type,
            confidence,
            authority,
            scenario_manifest,
            capture_manifest,
            limitation_count,
            analysis_profile_digest: profile_digest,
        })
    }

    /// Complete canonical record, retaining every provider payload field.
    pub fn raw(&self) -> &RawValue {
        &self.raw
    }

    /// Authenticated normalized provider payload, retained without decoding.
    pub fn normalized_result(&self) -> &RawValue {
        let shape: RecordShape<'_> = decode(&self.raw).expect("validated Evidence record");
        shape.normalized_result
    }

    /// Authenticated semantic identifier.
    pub fn evidence_id(&self) -> &str {
        &self.evidence_id
    }

    /// Subject digest, or unknown when the observation has no subject.
    pub fn subject_sha256(&self) -> Option<&str> {
        self.subject_sha256.as_deref()
    }

    /// Original subject projection for record summaries.
    pub fn subject(&self) -> &RawValue {
        &self.subject
    }

    /// Canonical artifact manifest, excluding display-only subject fields.
    pub fn artifact_manifest(&self) -> Option<&RawValue> {
        self.artifact_manifest.as_deref()
    }

    /// Provider manifest retained without converting source strings.
    pub fn provider_manifest(&self) -> &RawValue {
        &self.provider_manifest
    }

    /// Environment manifest when the record names an environment.
    pub fn environment_manifest(&self) -> Option<&RawValue> {
        self.environment_manifest.as_deref()
    }

    /// Confidence enum as its original JSON string.
    pub fn confidence(&self) -> &RawValue {
        &self.confidence
    }

    /// Authority enum as its original JSON string.
    pub fn authority(&self) -> &RawValue {
        &self.authority
    }

    /// Number of retained limitations, without copying their text.
    pub fn limitation_count(&self) -> usize {
        self.limitation_count
    }

    /// Scenario manifest when the authenticated record is controlled replay.
    pub fn scenario_manifest(&self) -> Option<&RawValue> {
        self.scenario_manifest.as_deref()
    }

    /// Process-capture manifest when the authenticated predicate is a capture.
    pub fn capture_manifest(&self) -> Option<&RawValue> {
        self.capture_manifest.as_deref()
    }

    /// Metadata projection for summary delivery without copying payloads.
    pub fn metadata(&self) -> EvidenceRecordMetadata<'_> {
        EvidenceRecordMetadata {
            evidence_id: &self.evidence_id,
            subject: &self.subject,
            provider: &self.provider_manifest,
            operation: &self.operation,
            confidence: &self.confidence,
            authority: &self.authority,
            analysis_profile_digest: self.analysis_profile_digest.as_deref(),
            limitation_count: self.limitation_count,
        }
    }

    /// Canonical operation value, including non-Unicode source code units.
    pub fn operation(&self) -> &RawValue {
        &self.operation
    }

    /// Match an operation selector without parsing or rewriting source strings.
    pub fn operation_matches(&self, value: &str) -> bool {
        serde_json::to_string(value).is_ok_and(|encoded| encoded == self.operation.get())
    }

    /// Canonical predicate value, including non-Unicode source code units.
    pub fn predicate_type(&self) -> &RawValue {
        &self.predicate_type
    }

    /// Authenticated profile digest, if a profile was supplied.
    pub fn analysis_profile_digest(&self) -> Option<&str> {
        self.analysis_profile_digest.as_deref()
    }

    /// Compare records using the same semantic fields as their identity.
    pub fn agrees(&self, other: &Self) -> Result<bool, EvidenceRecordError> {
        if self.evidence_id != other.evidence_id {
            return Ok(false);
        }

        Ok(semantic_bytes(&self.raw)? == semantic_bytes(&other.raw)?)
    }
}

impl Serialize for EvidenceRecord {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.raw.serialize(serializer)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordShape<'a> {
    evidence_id: String,
    #[serde(borrow)]
    subject: &'a RawValue,
    #[serde(borrow)]
    provider: &'a RawValue,
    #[serde(borrow)]
    analysis_profile: &'a RawValue,
    #[serde(borrow)]
    predicate_type: &'a RawValue,
    #[serde(borrow)]
    operation: &'a RawValue,
    #[serde(borrow)]
    parameters: &'a RawValue,
    #[serde(borrow)]
    raw_result: &'a RawValue,
    #[serde(borrow)]
    normalized_result: &'a RawValue,
    #[serde(borrow)]
    confidence: &'a RawValue,
    #[serde(borrow)]
    authority: &'a RawValue,
    #[serde(borrow)]
    environment: &'a RawValue,
    #[serde(borrow)]
    limitations: &'a RawValue,
    #[serde(borrow)]
    relationship_coverage: &'a RawValue,
    #[serde(borrow)]
    locations: &'a RawValue,
    #[serde(borrow)]
    evidence_links: &'a RawValue,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SubjectShape<'a> {
    name: JsonText,
    #[serde(borrow)]
    digest: &'a RawValue,
    format: String,
    #[serde(borrow)]
    architecture: &'a RawValue,
    local_path: JsonText,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DigestShape {
    sha256: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProviderShape<'a> {
    id: JsonText,
    name: JsonText,
    #[serde(borrow)]
    version: &'a RawValue,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileShape<'a> {
    #[serde(borrow)]
    provider: &'a RawValue,
    #[serde(borrow)]
    parameters: &'a RawValue,
    digest: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EnvironmentShape {
    id: JsonText,
    platform: JsonText,
    architecture: JsonText,
    isolation: String,
}

#[derive(Default)]
struct OptionalRaw(Option<Box<RawValue>>);

impl<'de> Deserialize<'de> for OptionalRaw {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Box::<RawValue>::deserialize(deserializer).map(|raw| Self(Some(raw)))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RelationshipCoverageShape {
    status: String,
    diagnostics: Vec<JsonText>,
    #[serde(default)]
    limitations: OptionalRaw,
    #[serde(default)]
    reason: OptionalRaw,
    #[serde(default)]
    limited_directions: OptionalRaw,
}

#[derive(Serialize)]
struct ProfileUnsigned<'a> {
    provider: &'a RawValue,
    parameters: &'a RawValue,
}

#[derive(Serialize)]
struct SemanticSubject<'a> {
    digest: &'a RawValue,
    format: &'a str,
    architecture: &'a RawValue,
}

#[derive(Serialize)]
struct ArtifactManifest<'a> {
    digest: &'a RawValue,
    format: &'a str,
    architecture: &'a RawValue,
}

#[derive(Serialize)]
struct ScenarioManifest<'a> {
    evidence_id: &'a str,
    operation: &'a RawValue,
    authority: &'a RawValue,
}

#[derive(Serialize)]
struct CaptureManifest<'a> {
    evidence_id: &'a str,
    predicate_type: &'a RawValue,
}

/// Small record summary metadata shared by every Evidence producer.
#[derive(Serialize)]
pub struct EvidenceRecordMetadata<'a> {
    evidence_id: &'a str,
    subject: &'a RawValue,
    provider: &'a RawValue,
    operation: &'a RawValue,
    confidence: &'a RawValue,
    authority: &'a RawValue,
    analysis_profile_digest: Option<&'a str>,
    limitation_count: usize,
}

#[derive(Serialize)]
struct Semantic<'a> {
    subject: Option<SemanticSubject<'a>>,
    provider: &'a RawValue,
    analysis_profile: &'a RawValue,
    predicate_type: &'a RawValue,
    operation: &'a RawValue,
    parameters: &'a RawValue,
    raw_result: &'a RawValue,
    normalized_result: &'a RawValue,
    confidence: &'a RawValue,
    authority: &'a RawValue,
    environment: &'a RawValue,
    limitations: &'a RawValue,
    relationship_coverage: &'a RawValue,
    locations: &'a RawValue,
    evidence_links: &'a RawValue,
}

fn canonicalize(input: &RawValue) -> Result<Box<RawValue>, EvidenceRecordError> {
    let mut bytes = Vec::new();
    canonical_json::write(input, &mut bytes).map_err(EvidenceRecordError::Canonical)?;
    let text = String::from_utf8(bytes).map_err(|error| {
        EvidenceRecordError::Invalid(format!("Canonical Evidence is not UTF-8: {error}"))
    })?;
    RawValue::from_string(text).map_err(EvidenceRecordError::Json)
}

fn copy_raw(raw: &RawValue) -> Result<Box<RawValue>, EvidenceRecordError> {
    RawValue::from_string(raw.get().to_owned()).map_err(EvidenceRecordError::Json)
}

fn decode<'de, T: Deserialize<'de>>(raw: &'de RawValue) -> Result<T, EvidenceRecordError> {
    serde_json::from_str(raw.get()).map_err(|error| EvidenceRecordError::Invalid(error.to_string()))
}

fn parse_subject(
    raw: &RawValue,
) -> Result<(Option<String>, Option<SubjectShape<'_>>), EvidenceRecordError> {
    if is_null(raw) {
        return Ok((None, None));
    }

    let subject: SubjectShape<'_> = decode(raw)?;
    require_nonempty(&subject.name, "subject.name")?;
    if subject
        .local_path
        .utf16_units()
        .map_err(invalid_text)?
        .contains(&0)
    {
        return invalid("subject.local_path cannot contain NUL");
    }
    validate_digest_object(subject.digest, "subject.digest.sha256")?;

    const FORMATS: &[&str] = &[
        "hopper",
        "analysis-database",
        "mach-o",
        "elf",
        "pe",
        "dos-mz",
        "dos-com",
        "raw-binary",
        "zip",
        "ipa",
        "apk",
        "msix",
        "appx",
        "hap",
        "hsp",
        "app-pack",
        "asar",
        "dmg",
        "pkg",
        "plist",
        "nib",
        "javascript",
        "source-map",
        "directory",
        "file",
        "unknown",
        "mach-o-universal",
        "javascript-bundle",
        "entitlements",
    ];
    if !FORMATS.contains(&subject.format.as_str()) {
        return invalid("subject.format is not supported");
    }

    if !is_null(subject.architecture) {
        let architecture: String = decode(subject.architecture)?;
        const ARCHITECTURES: &[&str] = &[
            "x86", "x86_64", "arm", "arm64", "mips", "6502", "riscv", "powerpc", "m68k", "hexagon",
        ];
        if !ARCHITECTURES.contains(&architecture.as_str()) {
            return invalid("subject.architecture is not supported");
        }
        if subject.format != "raw-binary" && matches!(architecture.as_str(), "6502" | "m68k") {
            return invalid("subject architecture is not valid for its format");
        }
    }

    let digest: DigestShape = decode(subject.digest)?;
    Ok((Some(digest.sha256), Some(subject)))
}

fn parse_provider(
    raw: &RawValue,
    committed: bool,
) -> Result<ProviderShape<'_>, EvidenceRecordError> {
    let provider: ProviderShape<'_> = decode(raw)?;
    require_nonempty(&provider.id, "provider.id")?;
    require_nonempty(&provider.name, "provider.name")?;
    if committed {
        let version: JsonText = decode(provider.version)?;
        require_nonempty(&version, "provider.version")?;
    } else if !is_null(provider.version) {
        let _: JsonText = decode(provider.version)?;
    }
    Ok(provider)
}

fn parse_profile(
    raw: &RawValue,
    observation_provider: &ProviderShape<'_>,
) -> Result<Option<String>, EvidenceRecordError> {
    if is_null(raw) {
        return Ok(None);
    }

    let profile: ProfileShape<'_> = decode(raw)?;
    require_object(profile.parameters, "analysis_profile.parameters")?;
    validate_digest(&profile.digest, "analysis_profile.digest")?;

    let committed = parse_provider(profile.provider, true)?;
    let committed_version = decode::<JsonText>(committed.version)?;
    let record_version = if is_null(observation_provider.version) {
        None
    } else {
        Some(decode::<JsonText>(observation_provider.version)?)
    };
    if committed.id.utf16_units().map_err(invalid_text)?
        != observation_provider
            .id
            .utf16_units()
            .map_err(invalid_text)?
        || committed.name.utf16_units().map_err(invalid_text)?
            != observation_provider
                .name
                .utf16_units()
                .map_err(invalid_text)?
        || Some(committed_version.utf16_units().map_err(invalid_text)?)
            != record_version
                .map(|version| version.utf16_units())
                .transpose()
                .map_err(invalid_text)?
    {
        return invalid("Analysis profile provider does not match Evidence provider");
    }

    let unsigned = ProfileUnsigned {
        provider: profile.provider,
        parameters: profile.parameters,
    };
    let raw_unsigned =
        serde_json::value::to_raw_value(&unsigned).map_err(EvidenceRecordError::Json)?;
    let calculated =
        canonical_json::digest_raw(&raw_unsigned).map_err(EvidenceRecordError::Canonical)?;
    if calculated != profile.digest {
        return invalid("Analysis profile digest does not match its parameters");
    }
    Ok(Some(profile.digest))
}

fn parse_environment(raw: &RawValue) -> Result<(), EvidenceRecordError> {
    if is_null(raw) {
        return Ok(());
    }
    let environment: EnvironmentShape = decode(raw)?;
    require_nonempty(&environment.id, "environment.id")?;
    require_nonempty(&environment.platform, "environment.platform")?;
    require_nonempty(&environment.architecture, "environment.architecture")?;
    if !["none", "process", "container", "virtual-machine"]
        .contains(&environment.isolation.as_str())
    {
        return invalid("environment.isolation is not supported");
    }
    Ok(())
}

fn semantic_projection<'a>(
    shape: &'a RecordShape<'_>,
    subject: Option<&'a SubjectShape<'_>>,
) -> Result<Box<RawValue>, EvidenceRecordError> {
    let semantic_subject = subject.map(|subject| SemanticSubject {
        digest: subject.digest,
        format: &subject.format,
        architecture: subject.architecture,
    });
    let semantic = Semantic {
        subject: semantic_subject,
        provider: shape.provider,
        analysis_profile: shape.analysis_profile,
        predicate_type: shape.predicate_type,
        operation: shape.operation,
        parameters: shape.parameters,
        raw_result: shape.raw_result,
        normalized_result: shape.normalized_result,
        confidence: shape.confidence,
        authority: shape.authority,
        environment: shape.environment,
        limitations: shape.limitations,
        relationship_coverage: shape.relationship_coverage,
        locations: shape.locations,
        evidence_links: shape.evidence_links,
    };
    serde_json::value::to_raw_value(&semantic).map_err(EvidenceRecordError::Json)
}

fn semantic_bytes(raw: &RawValue) -> Result<Vec<u8>, EvidenceRecordError> {
    let shape: RecordShape<'_> = decode(raw)?;
    let (_, subject) = parse_subject(shape.subject)?;
    let semantic = semantic_projection(&shape, subject.as_ref())?;
    let mut bytes = Vec::new();
    canonical_json::write(&semantic, &mut bytes).map_err(EvidenceRecordError::Canonical)?;
    Ok(bytes)
}

fn validate_relationship_coverage(raw: &RawValue) -> Result<(), EvidenceRecordError> {
    if is_null(raw) {
        return Ok(());
    }
    let coverage: RelationshipCoverageShape = decode(raw)?;
    validate_nonempty_texts(&coverage.diagnostics, "relationship_coverage.diagnostics")?;

    match coverage.status.as_str() {
        "complete" => {
            reject_present(&coverage.limitations, "complete relationship coverage")?;
            reject_present(&coverage.reason, "complete relationship coverage")?;
            reject_present(
                &coverage.limited_directions,
                "complete relationship coverage",
            )?;
        }
        "partial" => {
            let limitations =
                required_optional(&coverage.limitations, "relationship_coverage.limitations")?;
            let limitations: Vec<JsonText> = decode(limitations)?;
            validate_nonempty_texts(&limitations, "relationship_coverage.limitations")?;
            reject_present(&coverage.reason, "partial relationship coverage")?;
            validate_optional_directions(&coverage.limited_directions)?;
        }
        "unknown" => {
            let reason = required_optional(&coverage.reason, "relationship_coverage.reason")?;
            validate_text(reason, "relationship_coverage.reason")?;
            reject_present(&coverage.limitations, "unknown relationship coverage")?;
            validate_optional_directions(&coverage.limited_directions)?;
        }
        _ => return invalid("relationship_coverage.status is not supported"),
    }
    Ok(())
}

fn validate_optional_directions(value: &OptionalRaw) -> Result<(), EvidenceRecordError> {
    let Some(raw) = &value.0 else {
        return Ok(());
    };
    let directions: Vec<JsonText> = decode(raw)?;
    let direction_values = directions
        .iter()
        .map(JsonText::as_str)
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| EvidenceRecordError::Invalid("invalid limited direction text".into()))?;
    let valid = matches!(direction_values.as_slice(), [first] if *first == "callers" || *first == "callees")
        || matches!(direction_values.as_slice(), [first, second] if *first == "callers" && *second == "callees");
    if valid {
        Ok(())
    } else {
        invalid("relationship_coverage.limited_directions is not a supported tuple")
    }
}

fn validate_locations(raw: &RawValue) -> Result<(), EvidenceRecordError> {
    let locations: Vec<&RawValue> = decode(raw)?;
    for location in locations {
        validate_location(location)?;
    }
    Ok(())
}

fn validate_location(raw: &RawValue) -> Result<(), EvidenceRecordError> {
    let mut fields: BTreeMap<String, Box<RawValue>> = decode(raw)?;
    let kind = take_location_field(&mut fields, "kind")?;
    let kind: String = decode(&kind)?;

    match kind.as_str() {
        "address" => validate_location_text(&mut fields, "address", "location.address")?,
        "address-range" => {
            validate_location_text(&mut fields, "start", "location.start")?;
            validate_location_text(&mut fields, "end", "location.end")?;
        }
        "artifact-path" => validate_location_text(&mut fields, "path", "location.path")?,
        "file-offset" => {
            let offset = take_location_field(&mut fields, "offset")?;
            validate_offset(&offset)?;
        }
        "file-offset-range" => {
            let start = take_location_field(&mut fields, "start")?;
            let end = take_location_field(&mut fields, "end")?;
            validate_offset(&start)?;
            validate_offset(&end)?;
        }
        _ => return invalid("Evidence location kind is not supported"),
    }

    if let Some(field) = fields.keys().next() {
        return invalid(format!("Evidence location has unexpected field {field}"));
    }

    Ok(())
}

fn validate_location_text(
    fields: &mut BTreeMap<String, Box<RawValue>>,
    field: &'static str,
    display_name: &'static str,
) -> Result<(), EvidenceRecordError> {
    let raw = take_location_field(fields, field)?;
    let value: JsonText = decode(&raw)?;
    require_nonempty(&value, display_name)
}

fn take_location_field(
    fields: &mut BTreeMap<String, Box<RawValue>>,
    field: &'static str,
) -> Result<Box<RawValue>, EvidenceRecordError> {
    fields.remove(field).ok_or_else(|| {
        EvidenceRecordError::Invalid(format!("Evidence location is missing {field}"))
    })
}

fn validate_offset(raw: &RawValue) -> Result<(), EvidenceRecordError> {
    let value: f64 = decode(raw)?;
    if value.is_finite() && value >= 0.0 && value.fract() == 0.0 {
        Ok(())
    } else {
        invalid("Evidence file offsets must be nonnegative integers")
    }
}

fn validate_evidence_links(raw: &RawValue) -> Result<(), EvidenceRecordError> {
    let links: Vec<String> = decode(raw)?;
    for link in links {
        validate_prefixed_digest(&link, "ev_")?;
    }
    Ok(())
}

fn validate_string_array(raw: &RawValue) -> Result<(), EvidenceRecordError> {
    let _: Vec<JsonText> = decode(raw)?;
    Ok(())
}

fn validate_nonempty_texts(
    values: &[JsonText],
    field: &'static str,
) -> Result<(), EvidenceRecordError> {
    if values.is_empty() {
        return invalid(format!("{field} must contain at least one item"));
    }
    for item in values {
        require_nonempty(item, field)?;
    }
    Ok(())
}

fn required_optional<'a>(
    value: &'a OptionalRaw,
    field: &'static str,
) -> Result<&'a RawValue, EvidenceRecordError> {
    value
        .0
        .as_deref()
        .ok_or_else(|| EvidenceRecordError::Invalid(format!("{field} is required")))
}

fn reject_present(value: &OptionalRaw, context: &'static str) -> Result<(), EvidenceRecordError> {
    if value.0.is_some() {
        invalid(format!(
            "{context} contains a field not admitted by its status"
        ))
    } else {
        Ok(())
    }
}

fn validate_enum(
    raw: &RawValue,
    choices: &[&str],
    field: &'static str,
) -> Result<(), EvidenceRecordError> {
    let value: String = decode(raw)?;
    if choices.contains(&value.as_str()) {
        Ok(())
    } else {
        invalid(format!("{field} is not supported"))
    }
}

fn validate_text(raw: &RawValue, field: &'static str) -> Result<(), EvidenceRecordError> {
    let value: JsonText = decode(raw)?;
    require_nonempty(&value, field)
}

fn require_object(raw: &RawValue, field: &'static str) -> Result<(), EvidenceRecordError> {
    if raw.get().starts_with('{') {
        Ok(())
    } else {
        invalid(format!("{field} must be an object"))
    }
}

fn validate_json(raw: &RawValue) -> Result<(), EvidenceRecordError> {
    canonical_json::digest_raw(raw)
        .map(|_| ())
        .map_err(EvidenceRecordError::Canonical)
}

fn validate_digest_object(raw: &RawValue, field: &'static str) -> Result<(), EvidenceRecordError> {
    let digest: DigestShape = decode(raw)?;
    validate_digest(&digest.sha256, field)
}

fn validate_digest(value: &str, field: &'static str) -> Result<(), EvidenceRecordError> {
    if is_sha256(value) {
        Ok(())
    } else {
        invalid(format!("{field} must be a lowercase SHA-256 digest"))
    }
}

fn validate_prefixed_digest(value: &str, prefix: &'static str) -> Result<(), EvidenceRecordError> {
    if value.strip_prefix(prefix).is_some_and(is_sha256) {
        Ok(())
    } else {
        invalid(format!(
            "Evidence identifier must use {prefix} followed by lowercase SHA-256"
        ))
    }
}

fn require_nonempty(value: &JsonText, field: &'static str) -> Result<(), EvidenceRecordError> {
    if value.utf16_units().map_err(invalid_text)?.is_empty() {
        invalid(format!("{field} must not be empty"))
    } else {
        Ok(())
    }
}

fn is_null(raw: &RawValue) -> bool {
    raw.get() == "null"
}

fn invalid_text(error: impl fmt::Display) -> EvidenceRecordError {
    EvidenceRecordError::Invalid(error.to_string())
}

fn invalid<T>(message: impl Into<String>) -> Result<T, EvidenceRecordError> {
    Err(EvidenceRecordError::Invalid(message.into()))
}
