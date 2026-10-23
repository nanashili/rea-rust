//! Deterministic provider-neutral Evidence construction.
//!
//! Compatibility owner: `createEvidence` in `src/domain/evidence.ts`. The
//! semantic identifier is the canonical SHA-256 of the semantic projection,
//! which excludes the display-only subject name and local path.
#![allow(missing_docs)]
use crate::canonical_json;
use serde::Serialize;
use serde_json::{Map, Value, json, value::RawValue};

/// Provider identity recorded in every Evidence envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EvidenceProvider {
    pub id: String,
    pub name: String,
    pub version: Option<String>,
}

impl EvidenceProvider {
    pub fn new(id: impl Into<String>, name: impl Into<String>, version: Option<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            version,
        }
    }
}

/// Immutable artifact identity for the Evidence subject.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubjectTarget {
    /// Caller-selected local path (display only; excluded from identity).
    pub path: String,
    pub sha256: String,
    /// Subject format, for example mach-o, elf, pe, apk or file.
    pub format: String,
    pub architecture: Option<String>,
}

/// One successful observation before identity assignment.
#[derive(Clone, Debug)]
pub struct Observation {
    /// Defaults to `rea.analysis`.
    pub predicate_type: Option<String>,
    pub operation: String,
    /// Caller/selection parameters; must be a JSON object.
    pub parameters: Value,
    pub result: Value,
    pub analysis_profile: Option<Value>,
    pub raw_result: Option<Value>,
    /// observed, derived or inferred; defaults to observed.
    pub confidence: Option<String>,
    /// Defaults to shipped-artifact.
    pub authority: Option<String>,
    pub environment: Option<Value>,
    pub limitations: Vec<String>,
    pub relationship_coverage: Option<Value>,
    /// Reason the subject identity is unavailable when no target is supplied.
    pub subject_unavailable_reason: Option<String>,
    pub locations: Vec<Value>,
    pub evidence_links: Vec<String>,
}

impl Observation {
    /// Minimal observation with every optional field at its default.
    pub fn new(operation: impl Into<String>, parameters: Value, result: Value) -> Self {
        Self {
            predicate_type: None,
            operation: operation.into(),
            parameters,
            result,
            analysis_profile: None,
            raw_result: None,
            confidence: None,
            authority: None,
            environment: None,
            limitations: Vec::new(),
            relationship_coverage: None,
            subject_unavailable_reason: None,
            locations: Vec::new(),
            evidence_links: Vec::new(),
        }
    }
    pub fn predicate(mut self, predicate_type: impl Into<String>) -> Self {
        self.predicate_type = Some(predicate_type.into());
        self
    }
    pub fn confidence(mut self, confidence: impl Into<String>) -> Self {
        self.confidence = Some(confidence.into());
        self
    }
    pub fn authority(mut self, authority: impl Into<String>) -> Self {
        self.authority = Some(authority.into());
        self
    }
    pub fn limitations(mut self, limitations: Vec<String>) -> Self {
        self.limitations = limitations;
        self
    }
    pub fn raw(mut self, raw_result: Value) -> Self {
        self.raw_result = Some(raw_result);
        self
    }
    pub fn links(mut self, evidence_links: Vec<String>) -> Self {
        self.evidence_links = evidence_links;
        self
    }
    pub fn locations(mut self, locations: Vec<Value>) -> Self {
        self.locations = locations;
        self
    }
    pub fn profile(mut self, analysis_profile: Value) -> Self {
        self.analysis_profile = Some(analysis_profile);
        self
    }
    pub fn coverage(mut self, relationship_coverage: Value) -> Self {
        self.relationship_coverage = Some(relationship_coverage);
        self
    }
    pub fn environment(mut self, environment: Value) -> Self {
        self.environment = Some(environment);
        self
    }
    pub fn subject_unavailable(mut self, reason: impl Into<String>) -> Self {
        self.subject_unavailable_reason = Some(reason.into());
        self
    }
}

/// Authenticated Evidence record with its semantic identifier.
#[derive(Clone, Debug, PartialEq)]
pub struct Evidence {
    id: String,
    value: Value,
}

impl Evidence {
    /// Build deterministic Evidence exactly as the original `createEvidence`.
    ///
    /// # Errors
    /// Canonicalization fails only for values outside JSON's numeric domain or
    /// beyond the shared nesting limit.
    pub fn create(
        target: Option<&SubjectTarget>,
        provider: &EvidenceProvider,
        observation: Observation,
    ) -> Result<Self, canonical_json::Error> {
        let mut limitations = Vec::with_capacity(observation.limitations.len() + 1);
        if target.is_none() {
            limitations.push(
                observation
                    .subject_unavailable_reason
                    .clone()
                    .unwrap_or_else(|| {
                        "Artifact identity is unavailable for this observation.".to_owned()
                    }),
            );
        }
        limitations.extend(observation.limitations);
        let semantic_subject = target.map(|target| {
            json!({
                "digest": { "sha256": target.sha256 },
                "format": target.format,
                "architecture": target.architecture,
            })
        });
        let provider_value = json!({
            "id": provider.id,
            "name": provider.name,
            "version": provider.version,
        });
        let predicate_type = observation
            .predicate_type
            .unwrap_or_else(|| "rea.analysis".to_owned());
        let confidence = observation
            .confidence
            .unwrap_or_else(|| "observed".to_owned());
        let authority = observation
            .authority
            .unwrap_or_else(|| "shipped-artifact".to_owned());
        let semantic = json!({
            "subject": semantic_subject,
            "provider": provider_value,
            "analysis_profile": observation.analysis_profile,
            "predicate_type": predicate_type,
            "operation": observation.operation,
            "parameters": observation.parameters,
            "raw_result": observation.raw_result,
            "normalized_result": observation.result,
            "confidence": confidence,
            "authority": authority,
            "environment": observation.environment,
            "limitations": limitations,
            "relationship_coverage": observation.relationship_coverage,
            "locations": observation.locations,
            "evidence_links": observation.evidence_links,
        });
        let id = format!("ev_{}", canonical_json::digest(&semantic)?);
        let Value::Object(mut semantic) = semantic else {
            unreachable!("semantic projection is an object")
        };
        // Envelope field order follows the original strict schema.
        let mut record = Map::new();
        record.insert("evidence_id".into(), Value::String(id.clone()));
        record.insert(
            "subject".into(),
            target.map_or(Value::Null, |target| {
                let name = std::path::Path::new(&target.path)
                    .file_name()
                    .and_then(|name| name.to_str())
                    .filter(|name| !name.is_empty())
                    .unwrap_or("artifact");
                json!({
                    "name": name,
                    "digest": { "sha256": target.sha256 },
                    "local_path": target.path,
                    "format": target.format,
                    "architecture": target.architecture,
                })
            }),
        );
        for key in [
            "provider",
            "analysis_profile",
            "predicate_type",
            "operation",
            "parameters",
            "raw_result",
            "normalized_result",
            "confidence",
            "authority",
            "environment",
            "limitations",
            "relationship_coverage",
            "locations",
            "evidence_links",
        ] {
            let value = semantic.remove(key).unwrap_or(Value::Null);
            record.insert(key.into(), value);
        }
        Ok(Self {
            id,
            value: Value::Object(record),
        })
    }

    /// Adopt an already-authenticated record (for example retained Evidence).
    pub fn from_authenticated(id: String, value: Value) -> Self {
        Self { id, value }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn value(&self) -> &Value {
        &self.value
    }

    pub fn into_value(self) -> Value {
        self.value
    }

    /// Lossless JSON text for retention.
    ///
    /// # Errors
    /// Serialization of a `Value` cannot fail except for allocation failure.
    pub fn to_raw(&self) -> Result<Box<RawValue>, serde_json::Error> {
        serde_json::value::to_raw_value(&self.value)
    }
}
