//! Function dossier projections and matching.
//!
//! Compatibility owner: `functionComparisonNormalization.ts`. Dossiers are the
//! already-parsed `functionDossierSchema` JSON of a [`super::snapshot::FunctionSnapshot`].

use super::canonical::canonical_json;
use crate::js::compare_code_points;
use num_bigint::{BigInt, BigUint};
use rea_core::analysis_error::AnalysisError;
use serde_json::{Value, json};
use std::cmp::Ordering;
use std::collections::BTreeSet;

const OPERATION: &str = "Function comparison";
const NORMALIZATION: &str = "Function normalization";

/// `isAutoName`: `sub_<hex>`, `fcn.<hex>` or `FUN_<hex>` (case-insensitive).
pub fn is_auto_name(name: &str) -> bool {
    fn is_hex(rest: &str) -> bool {
        !rest.is_empty() && rest.bytes().all(|byte| byte.is_ascii_hexdigit())
    }
    let lower = name.to_ascii_lowercase();
    if let Some(rest) = lower.strip_prefix("sub_") {
        return is_hex(rest);
    }
    if let Some(rest) = lower.strip_prefix("fcn.") {
        return is_hex(rest);
    }
    if let Some(rest) = lower.strip_prefix("fun_") {
        return is_hex(rest);
    }
    false
}

/// `parseAddress`: `0x<lower-hex>` to a non-negative integer.
fn parse_address(value: &str) -> Option<BigInt> {
    let digits = value.strip_prefix("0x")?;
    if digits.is_empty()
        || !digits
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return None;
    }
    BigUint::parse_bytes(digits.as_bytes(), 16).map(BigInt::from)
}

/// `relativeAddress`: the non-negative offset of `value` from `base`.
fn relative_address(value: &str, base: &str) -> Option<String> {
    let parsed = parse_address(value)?;
    let parsed_base = parse_address(base)?;
    if parsed < parsed_base {
        return None;
    }
    Some((parsed - parsed_base).to_string())
}

/// `sorted`: stable order by canonical JSON under code-point comparison.
pub fn sorted(values: Vec<Value>) -> Result<Vec<Value>, AnalysisError> {
    let mut keyed: Vec<(String, Value)> = Vec::with_capacity(values.len());
    for value in values {
        let json = canonical_json(&value, NORMALIZATION)?;
        keyed.push((json, value));
    }
    keyed.sort_by(|left, right| compare_code_points(&left.0, &right.0));
    Ok(keyed.into_iter().map(|(_, value)| value).collect())
}

fn procedure<'a>(dossier: &'a Value) -> &'a Value {
    &dossier["procedure"]
}

/// `identityProjection`.
pub fn identity_projection(dossier: &Value) -> Value {
    let proc = procedure(dossier);
    let mut locals: Vec<String> = proc["locals"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|local| local["description"].as_str().map(str::to_owned))
        .collect();
    // JavaScript default Array.prototype.sort (UTF-16 code-unit order).
    locals.sort_by(|a, b| crate::js::compare_utf16(a, b));
    json!({
        "name": proc["name"],
        "signature": proc["signature"],
        "locals": locals,
    })
}

/// `normalizeCfg`.
pub fn normalize_cfg(blocks: &[Value]) -> Option<Vec<Value>> {
    struct Parsed<'a> {
        block: &'a Value,
        start: BigInt,
        end: BigInt,
    }
    let mut parsed: Vec<Parsed> = Vec::with_capacity(blocks.len());
    for block in blocks {
        let start = parse_address(block["start"].as_str()?)?;
        let end = parse_address(block["end"].as_str()?)?;
        if end <= start {
            return None;
        }
        parsed.push(Parsed { block, start, end });
    }
    parsed.sort_by(|left, right| left.start.cmp(&right.start));
    // Distinct starts.
    let mut starts = BTreeSet::new();
    for item in &parsed {
        if !starts.insert(item.start.clone()) {
            return None;
        }
    }
    let indices: std::collections::HashMap<BigInt, usize> = parsed
        .iter()
        .enumerate()
        .map(|(index, item)| (item.start.clone(), index))
        .collect();
    let mut graph = Vec::with_capacity(parsed.len());
    for item in &parsed {
        let mut successors: Vec<i64> = Vec::new();
        for successor in item.block["successors"].as_array().into_iter().flatten() {
            let parsed_address = parse_address(successor.as_str()?)?;
            let index = indices.get(&parsed_address)?;
            successors.push(*index as i64);
        }
        successors.sort_unstable();
        graph.push(json!({
            "size": (&item.end - &item.start).to_string(),
            "successors": successors,
        }));
    }
    Some(graph)
}

/// `commentProjection`.
pub fn comment_projection(dossier: &Value) -> Result<Option<Vec<Value>>, AnalysisError> {
    let base = procedure(dossier)["address"].as_str().unwrap_or_default();
    let mut values = Vec::new();
    let mut any_null = false;
    for comment in dossier["comments"].as_array().into_iter().flatten() {
        let offset = comment["address"]
            .as_str()
            .and_then(|address| relative_address(address, base));
        if offset.is_none() {
            any_null = true;
        }
        values.push(json!({
            "offset": offset,
            "kind": comment["kind"],
            "text": comment["text"],
        }));
    }
    if any_null {
        return Ok(None);
    }
    Ok(Some(sorted(values)?))
}

/// `stringAndNameProjection`.
pub fn string_and_name_projection(
    dossier: &Value,
    include_swift_literals: bool,
) -> Result<Option<Vec<Value>>, AnalysisError> {
    let base = procedure(dossier)["address"].as_str().unwrap_or_default();
    let mut values = Vec::new();
    let mut any_null = false;
    let mut push_offset = |source: Option<&str>, build: &dyn Fn(Option<String>) -> Value| {
        let offset = source.and_then(|address| relative_address(address, base));
        if offset.is_none() {
            any_null = true;
        }
        values.push(build(offset));
    };

    for referenced in dossier["referenced_strings"]
        .as_array()
        .into_iter()
        .flatten()
    {
        let value = referenced["value"].clone();
        push_offset(
            referenced["source_address"].as_str(),
            &|offset| json!({ "kind": "string", "source_offset": offset, "value": value }),
        );
    }
    for referenced in dossier["referenced_names"].as_array().into_iter().flatten() {
        let value = referenced["value"].clone();
        push_offset(
            referenced["source_address"].as_str(),
            &|offset| json!({ "kind": "name", "source_offset": offset, "value": value }),
        );
    }
    if include_swift_literals {
        for literal in dossier["swift_string_literals"]
            .as_array()
            .into_iter()
            .flatten()
        {
            let value = literal["value"].clone();
            let representation = literal["representation"].clone();
            let registers = literal["registers"].clone();
            push_offset(literal["source_address"].as_str(), &|offset| {
                json!({
                    "kind": "swift_string",
                    "source_offset": offset,
                    "value": value,
                    "representation": representation,
                    "registers": registers,
                })
            });
        }
    }
    drop(push_offset);
    if any_null {
        return Ok(None);
    }
    Ok(Some(sorted(values)?))
}

/// Whether a retained Swift literal established a differing fact; see
/// `swiftLiteralSitesConflict`.
pub fn swift_literal_sites_conflict(left: &Value, right: &Value) -> Result<bool, AnalysisError> {
    let left_sites = swift_literal_sites(left)?;
    let right_sites = swift_literal_sites(right)?;
    let mut sites: BTreeSet<String> = BTreeSet::new();
    sites.extend(left_sites.values.keys().cloned());
    sites.extend(right_sites.values.keys().cloned());
    for site in sites {
        let left_values = match left_sites.values.get(&site) {
            Some(values) => Some(values.clone()),
            None if left_sites.complete => Some(Vec::new()),
            None => None,
        };
        let right_values = match right_sites.values.get(&site) {
            Some(values) => Some(values.clone()),
            None if right_sites.complete => Some(Vec::new()),
            None => None,
        };
        let (Some(left_values), Some(right_values)) = (left_values, right_values) else {
            continue;
        };
        let left_facts: BTreeSet<&String> = left_values.iter().collect();
        let right_facts: BTreeSet<&String> = right_values.iter().collect();
        if (right_sites.complete && left_values.iter().any(|value| !right_facts.contains(value)))
            || (left_sites.complete && right_values.iter().any(|value| !left_facts.contains(value)))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

struct SwiftSites {
    values: std::collections::BTreeMap<String, Vec<String>>,
    complete: bool,
}

fn swift_literal_sites(dossier: &Value) -> Result<SwiftSites, AnalysisError> {
    let base = procedure(dossier)["address"].as_str().unwrap_or_default();
    let omissions_len = dossier["swift_string_literal_omissions"]
        .as_array()
        .map(|array| array.len())
        .unwrap_or(0);
    let literals_present = dossier
        .get("swift_string_literals")
        .is_some_and(|value| !value.is_null());
    let mut values: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    for literal in dossier["swift_string_literals"]
        .as_array()
        .into_iter()
        .flatten()
    {
        let offset = literal["source_address"]
            .as_str()
            .and_then(|address| relative_address(address, base));
        let Some(offset) = offset else { continue };
        let key = canonical_json(&json!([offset, literal["registers"]]), OPERATION)?;
        let fact = canonical_json(
            &json!([literal["value"], literal["representation"]]),
            OPERATION,
        )?;
        let entry = values.entry(key).or_default();
        entry.push(fact);
        entry.sort_by(|a, b| compare_code_points(a, b));
    }
    Ok(SwiftSites {
        values,
        complete: literals_present && omissions_len == 0,
    })
}

/// Parsed function match result.
pub struct FunctionMatch {
    pub status: &'static str,
    pub method: &'static str,
    pub left_name: String,
    pub right_name: String,
}

impl FunctionMatch {
    pub fn to_value(&self) -> Value {
        json!({
            "status": self.status,
            "method": self.method,
            "left_name": self.left_name,
            "right_name": self.right_name,
        })
    }
}

/// `functionMatch`.
pub fn function_match(left: &Value, right: &Value) -> FunctionMatch {
    let left_name = procedure(left)["name"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let right_name = procedure(right)["name"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let stable_names = !is_auto_name(&left_name) && !is_auto_name(&right_name);
    if stable_names && left_name == right_name {
        return FunctionMatch {
            status: "matched",
            method: "symbol",
            left_name,
            right_name,
        };
    }
    FunctionMatch {
        status: if stable_names {
            "mismatched"
        } else {
            "ambiguous"
        },
        method: "explicit",
        left_name,
        right_name,
    }
}

/// Order a vector of JSON values by code-point comparison of canonical text.
pub fn code_point_order(left: &str, right: &str) -> Ordering {
    compare_code_points(left, right)
}
