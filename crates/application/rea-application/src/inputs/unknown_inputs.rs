//! Strict parsing and Zod-compatible normalization for unknown mutations.
use super::{InputError, Parser};
use rea_core::failure::InputIssue;
use serde_json::{Map, Number, Value, value::RawValue};

const STATUSES: &[&str] = &[
    "open",
    "investigating",
    "blocked",
    "contradicted",
    "resolved",
];
const SEVERITIES: &[&str] = &["low", "medium", "high", "critical"];
const AUTHORITIES: &[&str] = &[
    "shipped-artifact",
    "controlled-replay",
    "historical-reference",
    "external-service",
    "analyst-inference",
];
const CONFIDENCE: &[&str] = &["observed", "derived", "inferred"];
const RELATIONSHIP_TYPES: &[&str] = &["depends-on", "related-to", "contradicts"];
const ISOLATIONS: &[&str] = &["none", "process", "container", "virtual-machine"];
const COMPARISON_DIMENSIONS: &[&str] = &[
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

/// Parse the normalized strict input for `record_unknown`.
pub fn record_unknown(object: &Map<String, Value>) -> Result<Box<RawValue>, InputError> {
    let mut parser = Parser::default();
    parser.unknown(
        object,
        &[
            "question",
            "severity",
            "domain",
            "comparison_conclusion_scope",
            "supporting_evidence_ids",
            "contradicting_evidence_ids",
            "required_authority",
            "required_confidence",
            "required_environment",
            "recommended_probes",
            "relationships",
        ],
        &[],
    );

    let question = trimmed_string(&mut parser, object.get("question"), &["question"]);
    let severity = enum_string(
        &mut parser,
        object.get("severity"),
        &["severity"],
        SEVERITIES,
    );
    let domain = trimmed_string(&mut parser, object.get("domain"), &["domain"]);
    let comparison_scope = object
        .get("comparison_conclusion_scope")
        .map(|value| parse_comparison_scope(&mut parser, value));
    let supporting = evidence_ids(
        &mut parser,
        object.get("supporting_evidence_ids"),
        &["supporting_evidence_ids"],
        false,
    );
    let contradicting = evidence_ids(
        &mut parser,
        object.get("contradicting_evidence_ids"),
        &["contradicting_evidence_ids"],
        false,
    );
    let required_authority = nullable_enum(
        &mut parser,
        object.get("required_authority"),
        &["required_authority"],
        AUTHORITIES,
    );
    let required_confidence = enum_string(
        &mut parser,
        object.get("required_confidence"),
        &["required_confidence"],
        CONFIDENCE,
    );
    let required_environment = parse_environment(&mut parser, object.get("required_environment"));
    let recommended_probes = parse_probes(&mut parser, object.get("recommended_probes"));
    let relationships = parse_relationships(&mut parser, object.get("relationships"));

    parser.finish(())?;

    let mut normalized = Map::new();
    insert(&mut normalized, "question", question);
    insert(&mut normalized, "severity", severity);
    insert(&mut normalized, "domain", domain);
    if let Some(comparison_scope) = comparison_scope {
        insert(
            &mut normalized,
            "comparison_conclusion_scope",
            comparison_scope,
        );
    }
    insert(&mut normalized, "supporting_evidence_ids", supporting);
    insert(&mut normalized, "contradicting_evidence_ids", contradicting);
    insert(&mut normalized, "required_authority", required_authority);
    insert(&mut normalized, "required_confidence", required_confidence);
    insert(
        &mut normalized,
        "required_environment",
        required_environment,
    );
    insert(&mut normalized, "recommended_probes", recommended_probes);
    insert(&mut normalized, "relationships", relationships);
    encode_normalized(normalized)
}

/// Parse the normalized strict input for `update_unknown`.
pub fn update_unknown(object: &Map<String, Value>) -> Result<Box<RawValue>, InputError> {
    let mut parser = Parser::default();
    parser.unknown(
        object,
        &[
            "unknown_id",
            "expected_revision",
            "status",
            "severity",
            "supporting_evidence_ids",
            "contradicting_evidence_ids",
            "required_authority",
            "required_confidence",
            "required_environment",
            "recommended_probes",
            "relationships",
            "resolution",
        ],
        &[],
    );

    let unknown_id = prefixed_digest(
        &mut parser,
        object.get("unknown_id"),
        &["unknown_id"],
        "unk_",
    );
    let expected_revision = parser.safe_integer(
        object.get("expected_revision"),
        &["expected_revision"],
        None,
        1,
    );
    let status = enum_string(&mut parser, object.get("status"), &["status"], STATUSES);
    let severity = enum_string(
        &mut parser,
        object.get("severity"),
        &["severity"],
        SEVERITIES,
    );
    let supporting = evidence_ids(
        &mut parser,
        object.get("supporting_evidence_ids"),
        &["supporting_evidence_ids"],
        true,
    );
    let contradicting = evidence_ids(
        &mut parser,
        object.get("contradicting_evidence_ids"),
        &["contradicting_evidence_ids"],
        true,
    );
    let required_authority = nullable_enum(
        &mut parser,
        object.get("required_authority"),
        &["required_authority"],
        AUTHORITIES,
    );
    let required_confidence = enum_string(
        &mut parser,
        object.get("required_confidence"),
        &["required_confidence"],
        CONFIDENCE,
    );
    let required_environment = parse_environment(&mut parser, object.get("required_environment"));
    let recommended_probes = parse_probes(&mut parser, object.get("recommended_probes"));
    let relationships = parse_relationships(&mut parser, object.get("relationships"));
    let resolution = parse_resolution(&mut parser, object.get("resolution"));

    parser.finish(())?;

    let mut normalized = Map::new();
    insert(&mut normalized, "unknown_id", unknown_id);
    insert(
        &mut normalized,
        "expected_revision",
        expected_revision.map_or(Value::Null, |revision| {
            Value::Number(Number::from(revision))
        }),
    );
    insert(&mut normalized, "status", status);
    insert(&mut normalized, "severity", severity);
    insert(&mut normalized, "supporting_evidence_ids", supporting);
    insert(&mut normalized, "contradicting_evidence_ids", contradicting);
    insert(&mut normalized, "required_authority", required_authority);
    insert(&mut normalized, "required_confidence", required_confidence);
    insert(
        &mut normalized,
        "required_environment",
        required_environment,
    );
    insert(&mut normalized, "recommended_probes", recommended_probes);
    insert(&mut normalized, "relationships", relationships);
    insert(&mut normalized, "resolution", resolution);
    encode_normalized(normalized)
}

fn trimmed_string(parser: &mut Parser, value: Option<&Value>, path: &[&str]) -> Value {
    let Some(text) = parser.string(value, path, true, true) else {
        return Value::Null;
    };
    let trimmed = super::trim_domain(text);
    if trimmed.is_empty() {
        parser.issue(
            path,
            "too_small",
            "Too small: expected string to have >=1 characters".into(),
        );
    }
    Value::String(trimmed.to_owned())
}

fn enum_string(
    parser: &mut Parser,
    value: Option<&Value>,
    path: &[&str],
    choices: &[&str],
) -> Value {
    let Some(value) = value else {
        parser.wrong_type(path, "string", None);
        return Value::Null;
    };
    parser
        .enum_string(Some(value), path, choices)
        .map_or(Value::Null, |text| Value::String(text.to_owned()))
}

fn nullable_enum(
    parser: &mut Parser,
    value: Option<&Value>,
    path: &[&str],
    choices: &[&str],
) -> Value {
    match value {
        Some(Value::Null) => Value::Null,
        Some(value) => enum_string(parser, Some(value), path, choices),
        None => {
            parser.wrong_type(path, "string", None);
            Value::Null
        }
    }
}

fn prefixed_digest(
    parser: &mut Parser,
    value: Option<&Value>,
    path: &[&str],
    prefix: &str,
) -> Value {
    let Some(text) = parser.string(value, path, true, true) else {
        return Value::Null;
    };
    let digest = text.strip_prefix(prefix);
    if !digest.is_some_and(is_lower_sha256) {
        parser.issue(
            path,
            "invalid_format",
            format!("Expected a {prefix} prefixed lowercase sha256 digest"),
        );
    }
    Value::String(text.to_owned())
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn evidence_ids(
    parser: &mut Parser,
    value: Option<&Value>,
    path: &[&str],
    required: bool,
) -> Value {
    let Some(value) = value else {
        if required {
            parser.wrong_type(path, "array", None);
            return Value::Null;
        }
        return Value::Array(Vec::new());
    };
    let Some(values) = value.as_array() else {
        parser.wrong_type(path, "array", Some(value));
        return Value::Null;
    };

    let normalized = values
        .iter()
        .map(|value| prefixed_digest(parser, Some(value), path, "ev_"))
        .collect();
    Value::Array(normalized)
}

fn parse_comparison_scope(parser: &mut Parser, value: &Value) -> Value {
    let Some(object) = value.as_object() else {
        parser.wrong_type(&["comparison_conclusion_scope"], "object", Some(value));
        return Value::Null;
    };
    parser.unknown(
        object,
        &["comparison_evidence_id", "dimensions"],
        &["comparison_conclusion_scope"],
    );

    let evidence_id = prefixed_digest(
        parser,
        object.get("comparison_evidence_id"),
        &["comparison_conclusion_scope", "comparison_evidence_id"],
        "ev_",
    );
    let dimensions = parse_dimensions(parser, object.get("dimensions"));

    let mut normalized = Map::new();
    insert(&mut normalized, "comparison_evidence_id", evidence_id);
    insert(&mut normalized, "dimensions", dimensions);
    Value::Object(normalized)
}

fn parse_dimensions(parser: &mut Parser, value: Option<&Value>) -> Value {
    let Some(value) = value else {
        parser.wrong_type(
            &["comparison_conclusion_scope", "dimensions"],
            "array",
            None,
        );
        return Value::Null;
    };
    let Some(dimensions) = value.as_array() else {
        parser.wrong_type(
            &["comparison_conclusion_scope", "dimensions"],
            "array",
            Some(value),
        );
        return Value::Null;
    };
    if dimensions.is_empty() {
        parser.issue(
            &["comparison_conclusion_scope", "dimensions"],
            "too_small",
            "Too small: expected array to have >=1 items".into(),
        );
    }

    let mut normalized = Vec::with_capacity(dimensions.len());
    let mut previous: Option<String> = None;
    for dimension in dimensions {
        let parsed = enum_string(
            parser,
            Some(dimension),
            &["comparison_conclusion_scope", "dimensions"],
            COMPARISON_DIMENSIONS,
        );
        if let Some(current) = parsed.as_str() {
            if previous.as_deref().is_some_and(|before| before >= current) {
                parser.issue(
                    &["comparison_conclusion_scope", "dimensions"],
                    "invalid_value",
                    "Comparison dimensions must be sorted and unique".into(),
                );
            }
            previous = Some(current.to_owned());
        }
        normalized.push(parsed);
    }
    Value::Array(normalized)
}

fn parse_environment(parser: &mut Parser, value: Option<&Value>) -> Value {
    let Some(value) = value else {
        parser.wrong_type(&["required_environment"], "object", None);
        return Value::Null;
    };
    if value.is_null() {
        return Value::Null;
    }
    let Some(object) = value.as_object() else {
        parser.wrong_type(&["required_environment"], "object", Some(value));
        return Value::Null;
    };
    parser.unknown(
        object,
        &["id", "platform", "architecture", "isolation"],
        &["required_environment"],
    );

    let id = nullable_nonempty_string(parser, object.get("id"), &["required_environment", "id"]);
    let platform = nullable_nonempty_string(
        parser,
        object.get("platform"),
        &["required_environment", "platform"],
    );
    let architecture = nullable_nonempty_string(
        parser,
        object.get("architecture"),
        &["required_environment", "architecture"],
    );
    let isolation = nullable_enum(
        parser,
        object.get("isolation"),
        &["required_environment", "isolation"],
        ISOLATIONS,
    );

    let mut normalized = Map::new();
    insert(&mut normalized, "id", id);
    insert(&mut normalized, "platform", platform);
    insert(&mut normalized, "architecture", architecture);
    insert(&mut normalized, "isolation", isolation);
    Value::Object(normalized)
}

fn nullable_nonempty_string(parser: &mut Parser, value: Option<&Value>, path: &[&str]) -> Value {
    match value {
        Some(Value::Null) => Value::Null,
        Some(value) => parser
            .string(Some(value), path, true, true)
            .map_or(Value::Null, |text| Value::String(text.to_owned())),
        None => {
            parser.wrong_type(path, "string", None);
            Value::Null
        }
    }
}

fn parse_probes(parser: &mut Parser, value: Option<&Value>) -> Value {
    let Some(value) = value else {
        parser.wrong_type(&["recommended_probes"], "array", None);
        return Value::Null;
    };
    let Some(probes) = value.as_array() else {
        parser.wrong_type(&["recommended_probes"], "array", Some(value));
        return Value::Null;
    };

    let normalized = probes
        .iter()
        .map(|probe| parse_probe(parser, probe))
        .collect();
    Value::Array(normalized)
}

fn parse_probe(parser: &mut Parser, value: &Value) -> Value {
    let Some(object) = value.as_object() else {
        parser.wrong_type(&["recommended_probes"], "object", Some(value));
        return Value::Null;
    };
    parser.unknown(object, &["operation", "rationale"], &["recommended_probes"]);
    let operation = parser
        .string(
            object.get("operation"),
            &["recommended_probes", "operation"],
            true,
            true,
        )
        .map_or(Value::Null, |text| Value::String(text.to_owned()));
    let rationale = trimmed_string(
        parser,
        object.get("rationale"),
        &["recommended_probes", "rationale"],
    );

    let mut normalized = Map::new();
    insert(&mut normalized, "operation", operation);
    insert(&mut normalized, "rationale", rationale);
    Value::Object(normalized)
}

fn parse_relationships(parser: &mut Parser, value: Option<&Value>) -> Value {
    let Some(value) = value else {
        parser.wrong_type(&["relationships"], "array", None);
        return Value::Null;
    };
    let Some(relationships) = value.as_array() else {
        parser.wrong_type(&["relationships"], "array", Some(value));
        return Value::Null;
    };

    let normalized = relationships
        .iter()
        .map(|relationship| parse_relationship(parser, relationship))
        .collect();
    Value::Array(normalized)
}

fn parse_relationship(parser: &mut Parser, value: &Value) -> Value {
    let Some(object) = value.as_object() else {
        parser.wrong_type(&["relationships"], "object", Some(value));
        return Value::Null;
    };
    parser.unknown(object, &["type", "unknown_id"], &["relationships"]);
    let kind = enum_string(
        parser,
        object.get("type"),
        &["relationships", "type"],
        RELATIONSHIP_TYPES,
    );
    let unknown_id = prefixed_digest(
        parser,
        object.get("unknown_id"),
        &["relationships", "unknown_id"],
        "unk_",
    );

    let mut normalized = Map::new();
    insert(&mut normalized, "type", kind);
    insert(&mut normalized, "unknown_id", unknown_id);
    Value::Object(normalized)
}

fn parse_resolution(parser: &mut Parser, value: Option<&Value>) -> Value {
    let Some(value) = value else {
        parser.wrong_type(&["resolution"], "object", None);
        return Value::Null;
    };
    if value.is_null() {
        return Value::Null;
    }
    let Some(object) = value.as_object() else {
        parser.wrong_type(&["resolution"], "object", Some(value));
        return Value::Null;
    };
    parser.unknown(
        object,
        &["disposition", "rationale", "evidence_ids"],
        &["resolution"],
    );
    let disposition = enum_string(
        parser,
        object.get("disposition"),
        &["resolution", "disposition"],
        &["verified", "withdrawn", "out-of-scope"],
    );
    let rationale = trimmed_string(
        parser,
        object.get("rationale"),
        &["resolution", "rationale"],
    );
    let evidence = evidence_ids(
        parser,
        object.get("evidence_ids"),
        &["resolution", "evidence_ids"],
        true,
    );
    if disposition.as_str() == Some("verified") && evidence.as_array().is_some_and(Vec::is_empty) {
        parser.issue(
            &["resolution", "evidence_ids"],
            "too_small",
            "Too small: expected array to have >=1 items".into(),
        );
    }

    let mut normalized = Map::new();
    insert(&mut normalized, "disposition", disposition);
    insert(&mut normalized, "rationale", rationale);
    insert(&mut normalized, "evidence_ids", evidence);
    Value::Object(normalized)
}

fn insert(target: &mut Map<String, Value>, key: &str, value: Value) {
    target.insert(key.to_owned(), value);
}

fn encode_normalized(object: Map<String, Value>) -> Result<Box<RawValue>, InputError> {
    serde_json::value::to_raw_value(&Value::Object(object)).map_err(|error| {
        InputError(vec![InputIssue {
            path: Vec::new(),
            reason: "invalid_value",
            message: format!("Could not normalize the input: {error}"),
            expected: None,
        }])
    })
}
