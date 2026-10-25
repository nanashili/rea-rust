//! Application-graph coverage and reconstruction evidence constructors
//! (`javascriptApplicationEvidenceSchemas` coverage helpers and
//! `JavaScriptArtifactGraphEvidence`).

use super::super::semantic::value_types::JsString;
use super::json::{Json, Obj};

/// `completeApplicationCoverage(limits)`.
pub fn complete_coverage() -> Json {
    coverage("complete", false, Json::Number(0.0), Vec::new())
}

/// `partialApplicationCoverage(limits, omittedCount)`.
pub fn partial_coverage(limits: Vec<Json>, omitted: Option<f64>) -> Json {
    coverage("partial", false, omitted.into(), limits)
}

/// `truncatedApplicationCoverage(limits, omittedCount)`.
pub fn truncated_coverage(limits: Vec<Json>, omitted: Option<f64>) -> Json {
    coverage("partial", true, omitted.into(), limits)
}

fn coverage(status: &str, truncated: bool, omitted: Json, limits: Vec<Json>) -> Json {
    Obj::new()
        .with("status", status)
        .with("truncated", truncated)
        .with("omitted_count", omitted)
        .with("limits", Json::Array(limits))
        .into()
}

/// One coverage limit record.
pub fn limit(name: &str, value: f64, unit: &str) -> Json {
    Obj::new()
        .with("name", name)
        .with("value", value)
        .with("unit", unit)
        .into()
}

const EXTRACTOR_NAME: &str = "rea-javascript-artifact-reconstruction";

/// Shared exact artifact location and bounded coverage for static evidence.
pub struct EvidenceInput<'a> {
    /// Content digest of the artifact holding the fact.
    pub sha256: &'a str,
    /// Exact UTF-16 logical artifact path.
    pub path: JsString,
    /// Extractor operation.
    pub operation: &'a str,
    /// Bounded coverage.
    pub coverage: Json,
    /// Additional limitations, when supplied.
    pub limitations: Option<Vec<JsString>>,
    /// Exact source range, when supplied.
    pub range: Option<&'a Json>,
}

impl<'a> EvidenceInput<'a> {
    /// Evidence input without limitations or range.
    pub fn new<P>(sha256: &'a str, path: P, operation: &'a str, coverage: Json) -> Self
    where
        P: Into<JsString>,
    {
        Self {
            sha256,
            path: path.into(),
            operation,
            coverage,
            limitations: None,
            range: None,
        }
    }

    /// Attach a source range.
    #[must_use]
    pub fn range(mut self, range: &'a Json) -> Self {
        self.range = Some(range);
        self
    }

    /// Attach limitations.
    #[must_use]
    pub fn limitations<T>(mut self, limitations: Vec<T>) -> Self
    where
        T: Into<JsString>,
    {
        self.limitations = Some(limitations.into_iter().map(Into::into).collect());
        self
    }
}

fn artifact_reference(sha256: &str) -> Json {
    Obj::new()
        .with("available", true)
        .with("artifact_id", format!("art_{sha256}"))
        .with("sha256", sha256)
        .into()
}

fn extractor(operation: &str) -> Json {
    Obj::new()
        .with("name", EXTRACTOR_NAME)
        .with("version", "1")
        .with("executable_sha256", Json::Null)
        .with("operation", operation)
        .into()
}

fn artifact_path_location(path: &JsString) -> Json {
    Obj::new()
        .with("available", true)
        .with(
            "value",
            Obj::new()
                .with("kind", "artifact-path")
                .with("path", Json::String(path.clone())),
        )
        .into()
}

/// `{ kind: "source-range", source, ...range }` location reference.
pub fn source_range_location(source: &JsString, range: &Json) -> Json {
    let mut value = Obj::new()
        .with("kind", "source-range")
        .with("source", Json::String(source.clone()));
    if let Some(range) = range.as_obj() {
        value.extend_from(range);
    }
    Obj::new()
        .with("available", true)
        .with("value", value)
        .into()
}

fn evidence(
    authority: &str,
    state: &str,
    confidence: &str,
    input: &EvidenceInput<'_>,
    location: Json,
    limitations: Vec<JsString>,
) -> Json {
    Obj::new()
        .with("authority", authority)
        .with("state", state)
        .with("confidence", confidence)
        .with("artifact", artifact_reference(input.sha256))
        .with("location", location)
        .with("extractor", extractor(input.operation))
        .with("coverage", input.coverage.clone())
        .with("limitations", super::json::strings(limitations))
        .with("evidence_ids", Json::Array(Vec::new()))
        .into()
}

/// `artifactObservationEvidence`.
pub fn artifact_observation(input: &EvidenceInput<'_>) -> Json {
    evidence(
        "artifact-bytes",
        "observed",
        "exact",
        input,
        artifact_path_location(&input.path),
        input.limitations.clone().unwrap_or_default(),
    )
}

/// `astObservationEvidence`; the input must carry a range.
pub fn ast_observation(input: &EvidenceInput<'_>) -> Json {
    let mut limitations = input.limitations.clone().unwrap_or_default();
    if input.coverage.at("status").str() != "complete" {
        limitations.push(
            JsString::from(
                "AST coverage is incomplete; omitted or dynamic facts must not be interpreted as absence.",
            ),
        );
    }
    let range = input.range.unwrap_or(&Json::Null);
    evidence(
        "ast-static-analysis",
        "observed",
        "exact",
        input,
        source_range_location(&input.path, range),
        limitations,
    )
}

/// `staticInferenceEvidence`.
pub fn static_inference(input: &EvidenceInput<'_>, confidence: Option<&str>) -> Json {
    let location = match input.range {
        None => artifact_path_location(&input.path),
        Some(range) => source_range_location(&input.path, range),
    };
    let mut limitations = vec![JsString::from(
        "Static syntax does not prove that this relationship executes at runtime.",
    )];
    limitations.extend(input.limitations.clone().unwrap_or_default());
    evidence(
        "static-relationship-inference",
        "inferred",
        confidence.unwrap_or("high"),
        input,
        location,
        limitations,
    )
}

/// `unavailableStaticEvidence`.
pub fn unavailable_static(
    input: &EvidenceInput<'_>,
    authority: &str,
    limitation: &JsString,
) -> Json {
    let mut limitations = vec![limitation.clone()];
    limitations.extend(input.limitations.clone().unwrap_or_default());
    evidence(
        authority,
        "unavailable",
        "unknown",
        input,
        artifact_path_location(&input.path),
        limitations,
    )
}
