//! Parsed endpoint/kind reference comparison.
//!
//! Compatibility owner: `functionReferenceComparison.ts`.

use super::canonical::canonical_json;
use super::native_address::parse_native_address;
use super::normalization::{is_auto_name, sorted};
use super::reference_compatibility::{ReferenceCompatibilityRow, reference_facts_compatible};
use super::snapshot::FunctionSnapshot;
use rea_core::analysis_error::AnalysisError;
use serde_json::{Map, Value, json};
use std::collections::{BTreeSet, HashMap};

const OPERATION: &str = "Comparison";

/// Status and parsed facts of a reference comparison.
pub struct ReferenceComparison {
    pub status: &'static str,
    pub left_count: usize,
    pub right_count: usize,
    pub limitations: Vec<String>,
    /// Present for `changed`/`unchanged` (sorted facts).
    pub left: Option<Vec<Value>>,
    pub right: Option<Vec<Value>>,
}

#[derive(Clone)]
enum Endpoint {
    Address {
        address: String,
    },
    Name {
        name: String,
        ambiguous: bool,
    },
    Unknown {
        reason: &'static str,
        reported_address: String,
        reported_name: Option<String>,
    },
}

impl Endpoint {
    fn to_value(&self) -> Value {
        match self {
            Endpoint::Address { address } => json!({ "kind": "address", "address": address }),
            Endpoint::Name { name, ambiguous } => {
                json!({ "kind": "name", "name": name, "ambiguous": ambiguous })
            }
            Endpoint::Unknown {
                reason,
                reported_address,
                reported_name,
            } => json!({
                "kind": "unknown",
                "reason": reason,
                "reported_address": reported_address,
                "reported_name": reported_name,
            }),
        }
    }

    /// `endpointKey`: canonical identity for a known endpoint, else `None`.
    fn key(&self, operation: &str) -> Result<Option<String>, AnalysisError> {
        match self {
            Endpoint::Unknown { .. } => Ok(None),
            Endpoint::Address { address } => {
                canonical_json(&json!({ "address": address }), operation).map(Some)
            }
            Endpoint::Name { name, .. } => {
                canonical_json(&json!({ "name": name }), operation).map(Some)
            }
        }
    }
}

struct ReferenceFact {
    direction: &'static str,
    source: Endpoint,
    target: Endpoint,
    /// Known kind object (without `available`/`provenance`), or `None`.
    kind: Option<Value>,
}

impl ReferenceFact {
    fn to_value(&self) -> Value {
        json!({
            "direction": self.direction,
            "source": self.source.to_value(),
            "target": self.target.to_value(),
            "kind": self.kind,
        })
    }
}

fn native_address(value: &Value) -> Option<String> {
    value.as_str().and_then(parse_native_address)
}

/// `ambiguousProcedureNames`.
fn ambiguous_procedure_names(snapshots: [&FunctionSnapshot; 2]) -> BTreeSet<String> {
    let mut ambiguous = BTreeSet::new();
    for snapshot in snapshots {
        let mut entries: HashMap<String, String> = HashMap::new();
        let mut observe = |procedure: &Value| {
            if procedure.is_null() {
                return;
            }
            let name = procedure["name"].as_str().unwrap_or_default().to_owned();
            match native_address(&procedure["address"]) {
                None => {
                    ambiguous.insert(name);
                }
                Some(address) => {
                    if let Some(previous) = entries.get(&name)
                        && *previous != address
                    {
                        ambiguous.insert(name.clone());
                    }
                    entries.insert(name, address);
                }
            }
        };
        observe(&snapshot.dossier["procedure"]);
        for edge in snapshot.dossier["incoming_references"]
            .as_array()
            .into_iter()
            .flatten()
        {
            observe(&edge["source_procedure"]);
            observe(&edge["target_procedure"]);
        }
        for edge in snapshot.dossier["outgoing_references"]
            .as_array()
            .into_iter()
            .flatten()
        {
            observe(&edge["source_procedure"]);
            observe(&edge["target_procedure"]);
        }
    }
    ambiguous
}

fn endpoint(
    procedure: &Value,
    address: &str,
    same_artifact: bool,
    ambiguous_names: &BTreeSet<String>,
) -> Endpoint {
    let procedure_name = if procedure.is_null() {
        None
    } else {
        procedure["name"].as_str().map(str::to_owned)
    };
    if same_artifact {
        if let Some(parsed) = parse_native_address(address) {
            return Endpoint::Address { address: parsed };
        }
        return Endpoint::Unknown {
            reason: "unparsed_address",
            reported_address: address.to_owned(),
            reported_name: procedure_name,
        };
    }
    let name = procedure_name.clone().unwrap_or_default();
    let is_auto = !procedure.is_null() && is_auto_name(&name);
    if procedure.is_null() || name.is_empty() || is_auto {
        return Endpoint::Unknown {
            reason: if !procedure.is_null() && is_auto {
                "generated_name"
            } else {
                "missing_name"
            },
            reported_address: address.to_owned(),
            reported_name: procedure_name,
        };
    }
    Endpoint::Name {
        ambiguous: ambiguous_names.contains(&name),
        name,
    }
}

/// `project`: endpoint/kind facts for one snapshot.
fn project(
    snapshot: &FunctionSnapshot,
    same_artifact: bool,
    ambiguous_names: &BTreeSet<String>,
) -> Vec<ReferenceFact> {
    let mut facts = Vec::new();
    let collect = |references: &Value, direction: &'static str, facts: &mut Vec<ReferenceFact>| {
        for edge in references.as_array().into_iter().flatten() {
            let kind = if edge["kind"]["available"] == Value::Bool(true) {
                let mut known = Map::new();
                if let Some(object) = edge["kind"].as_object() {
                    for (key, value) in object {
                        if key == "available" || key == "provenance" {
                            continue;
                        }
                        known.insert(key.clone(), value.clone());
                    }
                }
                Some(Value::Object(known))
            } else {
                None
            };
            facts.push(ReferenceFact {
                direction,
                source: endpoint(
                    &edge["source_procedure"],
                    edge["source_address"].as_str().unwrap_or_default(),
                    same_artifact,
                    ambiguous_names,
                ),
                target: endpoint(
                    &edge["target_procedure"],
                    edge["target_address"].as_str().unwrap_or_default(),
                    same_artifact,
                    ambiguous_names,
                ),
                kind,
            });
        }
    };
    collect(&snapshot.dossier["incoming_references"], "in", &mut facts);
    collect(&snapshot.dossier["outgoing_references"], "out", &mut facts);
    facts
}

fn constraints(
    facts: &[ReferenceFact],
    operation: &str,
) -> Result<Vec<ReferenceCompatibilityRow>, AnalysisError> {
    let mut rows = Vec::with_capacity(facts.len());
    for fact in facts {
        let kind = match &fact.kind {
            None => None,
            Some(value) => Some(canonical_json(value, operation)?),
        };
        rows.push(ReferenceCompatibilityRow {
            direction: fact.direction,
            source: fact.source.key(operation)?,
            target: fact.target.key(operation)?,
            kind,
        });
    }
    Ok(rows)
}

fn sorted_facts(facts: &[ReferenceFact]) -> Result<Vec<Value>, AnalysisError> {
    sorted(facts.iter().map(ReferenceFact::to_value).collect())
}

/// `compareFunctionReferences`.
pub fn compare_function_references(
    left: &FunctionSnapshot,
    right: &FunctionSnapshot,
) -> Result<ReferenceComparison, AnalysisError> {
    let same_artifact = left.subject_sha256() == right.subject_sha256();
    let ambiguous_names = if same_artifact {
        BTreeSet::new()
    } else {
        ambiguous_procedure_names([left, right])
    };
    let left_facts = project(left, same_artifact, &ambiguous_names);
    let right_facts = project(right, same_artifact, &ambiguous_names);

    let mut unknown_identity = false;
    let mut ambiguous_identity = false;
    let mut unknown_kinds = false;
    for facts in [&left_facts, &right_facts] {
        for fact in facts {
            unknown_kinds |= fact.kind.is_none();
            for endpoint in [&fact.source, &fact.target] {
                match endpoint {
                    Endpoint::Unknown { .. } => unknown_identity = true,
                    Endpoint::Name { ambiguous, .. } => ambiguous_identity |= *ambiguous,
                    Endpoint::Address { .. } => {}
                }
            }
        }
    }

    let mut limitations: Vec<String> = Vec::new();
    if unknown_identity {
        limitations.push(
            if same_artifact {
                "Reference endpoint coordinates could not be parsed, so their identity remains unknown."
            } else {
                "Unnamed reference endpoints and generated procedure names have no stable identity across different artifacts."
            }
            .to_owned(),
        );
    }
    if ambiguous_identity {
        limitations.push(
            "A reference name does not uniquely identify an observed procedure entry, so matching names do not establish equal endpoints."
                .to_owned(),
        );
    }
    if unknown_kinds {
        limitations.push(
            "At least one provider did not expose reference kinds, so compatible endpoints do not prove equal edge semantics."
                .to_owned(),
        );
    }

    let left_count = left_facts.len();
    let right_count = right_facts.len();

    let left_rows = constraints(&left_facts, OPERATION)?;
    let right_rows = constraints(&right_facts, OPERATION)?;
    if !reference_facts_compatible(&left_rows, &right_rows) {
        let mut changed_limitations = Vec::with_capacity(limitations.len() + 1);
        changed_limitations.push(
            "Known reference facts cannot be paired without contradicting an endpoint or reference kind.".to_owned(),
        );
        changed_limitations.extend(limitations);
        return Ok(ReferenceComparison {
            status: "changed",
            left_count,
            right_count,
            limitations: changed_limitations,
            left: Some(sorted_facts(&left_facts)?),
            right: Some(sorted_facts(&right_facts)?),
        });
    }

    if unknown_identity || ambiguous_identity || unknown_kinds {
        return Ok(ReferenceComparison {
            status: "unknown",
            left_count,
            right_count,
            limitations,
            left: None,
            right: None,
        });
    }

    Ok(ReferenceComparison {
        status: "unchanged",
        left_count,
        right_count,
        limitations,
        left: Some(sorted_facts(&left_facts)?),
        right: Some(sorted_facts(&right_facts)?),
    })
}
