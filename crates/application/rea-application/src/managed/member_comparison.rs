//! Bounded managed-member comparison over authenticated inspection results.
//!
//! Metadata tokens remain side-local. Matching uses declaring type, member
//! name, and decoded signature identity, then reports ambiguous duplicates as
//! unknown instead of guessing.

use crate::managed::artifact::project_member_evidence;
use rea_core::canonical_json;
use rea_rust_analysis::managed;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Compare two `inspect_managed_members` Evidence records.
pub fn compare(input: &Value) -> Result<Value, String> {
    let left = Side::parse(input.get("left").ok_or("left Evidence is required")?)?;
    let right = Side::parse(input.get("right").ok_or("right Evidence is required")?)?;
    if left.evidence_id == right.evidence_id {
        return Err("managed member Evidence must be distinct".into());
    }

    let methods = compare_collection(&left, &right, "methods", "mmc_method")?;
    let fields = compare_collection(&left, &right, "fields", "mmc_field")?;
    let summary = summary(&methods, &fields);
    let result = json!({
        "algorithm": {"name":"rea-managed-member-comparison","token_identity":"build-local","name_matching":"exact-signature-fallback"},
        "left": left.manifest(),
        "right": right.manifest(),
        "summary": summary,
        "matching": matching(&methods, &fields),
        "methods": methods,
        "fields": fields,
        "coverage": {"status": if left.complete && right.complete && same_selection(&left, &right) {"complete-within-inputs"} else {"partial"}, "left_status": left.coverage_status(), "right_status": right.coverage_status()},
        "evidence_links": [left.evidence_id, right.evidence_id],
        "limitations": ["Managed tokens are build-local and are retained only as side-specific identities.", "Only exact declaring-type/name/signature keys are paired; duplicate keys remain unknown."]
    });
    let comparison_id = format!("mmc_{}", digest(&result)?);
    let mut output = result;
    output["comparison_id"] = Value::String(comparison_id);
    Ok(output)
}

/// Compare two caller-owned managed artifact snapshots.
///
/// The runtime adapters may acquire the bytes through their bounded file
/// owner; this application boundary only parses each admitted snapshot and
/// feeds the resulting artifact-bound member records through the same
/// comparison algorithm used for retained Evidence.
pub fn compare_captured(
    left_path: &str,
    left_bytes: &[u8],
    right_path: &str,
    right_bytes: &[u8],
) -> Result<Value, String> {
    let left = captured_side(left_path, left_bytes)?;
    let right = captured_side(right_path, right_bytes)?;

    compare(&json!({"left": left, "right": right}))
}

fn captured_side(path: &str, bytes: &[u8]) -> Result<Value, String> {
    if path.is_empty() || path.contains('\0') {
        return Err("managed artifact path must be non-empty and NUL-free".into());
    }
    if bytes.len() > managed::MAX_INPUT_BYTES {
        return Err("managed artifact exceeds the input limit".into());
    }

    let inspection = managed::inspect(bytes)
        .map_err(|error| format!("managed artifact inspection failed: {error}"))?;
    let sha256 = format!("{:x}", Sha256::digest(bytes));
    let report = project_member_evidence(path, &sha256, &inspection, None);
    let normalized_result = serde_json::to_value(report)
        .map_err(|error| format!("managed member report could not be encoded: {error}"))?;
    let evidence_id = format!(
        "mme_{}",
        canonical_json::digest(&json!({"path": path, "sha256": sha256}))
            .map_err(|error| error.to_string())?
    );

    Ok(json!({
        "evidence_id": evidence_id,
        "operation": "inspect_managed_members",
        "normalized_result": normalized_result,
    }))
}

#[derive(Clone, Copy)]
struct Side<'a> {
    evidence_id: &'a str,
    result: &'a Value,
    payload: &'a Value,
    complete: bool,
    inventory_complete: bool,
}

impl<'a> Side<'a> {
    fn parse(evidence: &'a Value) -> Result<Self, String> {
        if evidence.get("operation").and_then(Value::as_str) != Some("inspect_managed_members") {
            return Err("Evidence operation is not inspect_managed_members".into());
        }
        let evidence_id = evidence
            .get("evidence_id")
            .and_then(Value::as_str)
            .ok_or("Evidence has no evidence_id")?;
        let result = evidence
            .get("normalized_result")
            .or_else(|| evidence.get("result"))
            .ok_or("Evidence has no normalized_result")?;
        let payload = result.get("members").unwrap_or(result);
        let complete = payload
            .pointer("/coverage/state")
            .and_then(Value::as_str)
            .unwrap_or("complete")
            == "complete";
        let inventory_complete = payload
            .pointer("/metadata/status")
            .and_then(Value::as_str)
            .unwrap_or("complete")
            == "complete";
        Ok(Self {
            evidence_id,
            result,
            payload,
            complete,
            inventory_complete,
        })
    }

    fn artifact_sha256(&self) -> Option<&str> {
        self.result
            .pointer("/artifact/sha256")
            .or_else(|| self.result.get("sha256"))
            .and_then(Value::as_str)
    }
    fn module(&self) -> Option<&Value> {
        self.payload.get("module").filter(|value| !value.is_null())
    }
    fn coverage_status(&self) -> &'static str {
        match self
            .payload
            .pointer("/coverage/state")
            .and_then(Value::as_str)
        {
            Some("unavailable") => "unavailable",
            Some("complete") if self.complete => "complete",
            _ => "partial",
        }
    }

    fn selection_covers(&self, row: &Value) -> bool {
        let Some(selected) = self
            .payload
            .pointer("/selection/type_names")
            .and_then(Value::as_array)
        else {
            return true;
        };
        let Some(declaring_type) = row.get("declaring_type").and_then(Value::as_str) else {
            return false;
        };
        selected
            .iter()
            .any(|value| value.as_str() == Some(declaring_type))
    }
    fn manifest(&self) -> Value {
        let metadata_status = self
            .payload
            .pointer("/metadata/status")
            .and_then(Value::as_str)
            .filter(|status| matches!(*status, "absent" | "complete" | "partial" | "malformed"))
            .unwrap_or("complete");
        json!({"evidence_id":self.evidence_id,"artifact_sha256":self.artifact_sha256().unwrap_or(""),"mvid":self.module().and_then(|m|m.get("mvid")).cloned().unwrap_or(Value::Null),"module_name":self.module().and_then(|m|m.get("name")).cloned().unwrap_or(Value::Null),"metadata_status":metadata_status,"methods_total":self.payload.get("methods").and_then(Value::as_array).map_or(0,Vec::len),"fields_total":self.payload.get("fields").and_then(Value::as_array).map_or(0,Vec::len)})
    }
}

fn compare_collection(
    left: &Side<'_>,
    right: &Side<'_>,
    collection: &str,
    prefix: &str,
) -> Result<Vec<Value>, String> {
    let left_rows = left
        .payload
        .get(collection)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let right_rows = right
        .payload
        .get(collection)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let left_map = index_rows(&left_rows);
    let right_map = index_rows(&right_rows);
    let mut keys = left_map
        .keys()
        .chain(right_map.keys())
        .cloned()
        .collect::<Vec<_>>();
    keys.sort();
    keys.dedup();
    let mut output = Vec::new();
    for key in keys {
        let l = left_map.get(&key).cloned().unwrap_or_default();
        let r = right_map.get(&key).cloned().unwrap_or_default();
        if l.is_empty() && r.len() == 1 {
            output.push(one_sided_item(
                prefix,
                r.first().expect("right group has one row"),
                false,
                left.evidence_id,
                right.evidence_id,
                left,
            ));
        } else if r.is_empty() && l.len() == 1 {
            output.push(one_sided_item(
                prefix,
                l.first().expect("left group has one row"),
                true,
                left.evidence_id,
                right.evidence_id,
                right,
            ));
        } else if l.is_empty() || r.is_empty() {
            let (rows, removed, opposite, left_id, right_id) = if l.is_empty() {
                (&r, false, left, left.evidence_id, right.evidence_id)
            } else {
                (&l, true, right, left.evidence_id, right.evidence_id)
            };
            for row in rows {
                let mut item = one_sided_item(prefix, row, removed, left_id, right_id, opposite);
                item["status"] = Value::String("unknown".into());
                item["limitations"] = json!([
                    "Duplicate members on one side prevent establishing absence on the other side."
                ]);
                output.push(item);
            }
        } else if l.len() != 1 || r.len() != 1 {
            output.push(ambiguous_item(
                prefix,
                &key,
                &l,
                &r,
                left.evidence_id,
                right.evidence_id,
            ));
        } else if let (Some(left_row), Some(right_row)) = (l.first(), r.first()) {
            output.push(matched_item(
                prefix,
                left_row,
                right_row,
                collection,
                left.evidence_id,
                right.evidence_id,
            ));
        }
    }
    Ok(output)
}

fn index_rows(rows: &[Value]) -> BTreeMap<String, Vec<Value>> {
    let mut index = BTreeMap::new();
    for row in rows {
        let declaring = row
            .get("declaring_type")
            .and_then(Value::as_str)
            .unwrap_or("");
        let name = row.get("name").and_then(Value::as_str).unwrap_or("");
        let signature = signature_identity(row).unwrap_or("");
        index
            .entry(format!("{declaring}\u{1f}{name}\u{1f}{signature}"))
            .or_insert_with(Vec::new)
            .push(row.clone());
    }
    index
}

fn signature_identity(row: &Value) -> Option<&str> {
    row.pointer("/signature/resolved_sha256")
        .and_then(Value::as_str)
        .or_else(|| row.pointer("/signature/raw_sha256").and_then(Value::as_str))
}

fn same_selection(left: &Side<'_>, right: &Side<'_>) -> bool {
    let left_selection = left
        .payload
        .pointer("/selection/type_names")
        .and_then(Value::as_array);
    let right_selection = right
        .payload
        .pointer("/selection/type_names")
        .and_then(Value::as_array);
    match (left_selection, right_selection) {
        (None, None) => true,
        (Some(left), Some(right)) => {
            let mut left_names = left.iter().filter_map(Value::as_str).collect::<Vec<_>>();
            let mut right_names = right.iter().filter_map(Value::as_str).collect::<Vec<_>>();
            left_names.sort_unstable();
            right_names.sort_unstable();
            left_names == right_names
        }
        _ => false,
    }
}

fn identity(row: &Value) -> Value {
    json!({"token":row.get("token").cloned().unwrap_or(Value::Null),"declaring_type":row.get("declaring_type").cloned().unwrap_or(Value::Null),"name":row.get("name").cloned().unwrap_or(Value::Null),"signature_sha256":row.pointer("/signature/raw_sha256").cloned().unwrap_or(Value::Null),"normalized_il_sha256":row.pointer("/body/normalized_il_sha256").cloned().unwrap_or(Value::Null)})
}
fn matched_item(
    prefix: &str,
    left: &Value,
    right: &Value,
    collection: &str,
    left_id: &str,
    right_id: &str,
) -> Value {
    let same_signature = signature_identity(left) == signature_identity(right);
    let (same_body, body_unknown) = if collection == "fields" {
        (true, false)
    } else {
        let left_complete = body_complete(left);
        let right_complete = body_complete(right);
        let equal = left.pointer("/body/il_sha256") == right.pointer("/body/il_sha256")
            && left.pointer("/body/normalized_il_sha256")
                == right.pointer("/body/normalized_il_sha256");
        (equal, !left_complete || !right_complete)
    };
    let status = if !same_signature {
        "changed"
    } else if body_unknown {
        "unknown"
    } else if same_body {
        "unchanged"
    } else {
        "changed"
    };
    let basis = if collection == "fields" {
        "field-signature"
    } else if same_signature && same_body && !body_unknown {
        "exact-il-signature"
    } else {
        "exact-signature"
    };
    let mut item = json!({"item_id":format!("{prefix}_{}", digest(&json!({"left":left.get("token"),"right":right.get("token")})).unwrap_or_else(|_|"unknown".into())),"status":status,"left":identity(left),"right":identity(right),"match":{"status":"matched","basis":basis,"confidence":if status == "unchanged" {"exact"} else {"high"},"candidate_left_tokens":[],"candidate_right_tokens":[]},"evidence_links":[left_id,right_id],"limitations":[]});
    if collection == "methods" {
        item["dimensions"] = if status == "unchanged" {
            json!([])
        } else {
            json!(["signature", "cil"])
        };
        if body_unknown {
            item["dimensions"] = json!(["body-coverage"]);
        }
        if !same_signature {
            item["dimensions"] = json!(["signature"]);
        }
        if same_signature && body_unknown {
            item["limitations"] = json!([
                "Method body facets are unknown because at least one side has unavailable or partial body data."
            ]);
        }
    }
    item
}
fn one_sided_item(
    prefix: &str,
    row: &Value,
    removed: bool,
    left_id: &str,
    right_id: &str,
    opposite: &Side<'_>,
) -> Value {
    let opposite_complete =
        opposite.complete && opposite.inventory_complete && opposite.selection_covers(row);
    let status = if opposite_complete {
        if removed { "removed" } else { "added" }
    } else {
        "unknown"
    };
    let mut item = json!({"item_id":format!("{prefix}_{}", digest(&json!({"token":row.get("token"),"removed":removed})).unwrap_or_else(|_|"unknown".into())),"status":status,"left":if removed {identity(row)} else {Value::Null},"right":if removed {Value::Null} else {identity(row)},"match":{"status":"unmatched","basis":"none","confidence":"unknown","candidate_left_tokens":[],"candidate_right_tokens":[]},"evidence_links":[left_id,right_id],"limitations":if opposite_complete {json!([])} else {json!(["The opposite managed member inventory is partial; absence was not established."])}});
    if prefix == "mmc_method" {
        item["dimensions"] = json!(["availability"]);
    }
    item
}

fn body_complete(row: &Value) -> bool {
    match row.pointer("/body/status").and_then(Value::as_str) {
        Some("present") => {
            row.pointer("/body/truncated_instructions")
                .and_then(Value::as_u64)
                .unwrap_or(0)
                == 0
        }
        Some(_) => false,
        None => row.pointer("/body/il_sha256").is_some(),
    }
}
fn ambiguous_item(
    prefix: &str,
    key: &str,
    left: &[Value],
    right: &[Value],
    left_id: &str,
    right_id: &str,
) -> Value {
    let mut item = json!({"item_id":format!("{prefix}_{}", digest(&json!({"key":key})).unwrap_or_else(|_|"unknown".into())),"status":"unknown","left":Value::Null,"right":Value::Null,"match":{"status":"ambiguous","basis":"exact-signature","confidence":"unknown","candidate_left_tokens":left.iter().filter_map(|row|row.get("token").and_then(Value::as_str)).collect::<Vec<_>>(),"candidate_right_tokens":right.iter().filter_map(|row|row.get("token").and_then(Value::as_str)).collect::<Vec<_>>()},"evidence_links":[left_id,right_id],"limitations":["Duplicate declaring-type/name/signature keys prevent a unique pairing."]});
    if prefix == "mmc_method" {
        item["dimensions"] = json!([]);
    }
    item
}
fn summary(methods: &[Value], fields: &[Value]) -> Value {
    let all = methods.iter().chain(fields);
    json!({"unchanged":all.clone().filter(|item|item["status"]=="unchanged").count(),"changed":all.clone().filter(|item|item["status"]=="changed").count(),"added":all.clone().filter(|item|item["status"]=="added").count(),"removed":all.clone().filter(|item|item["status"]=="removed").count(),"unknown":all.filter(|item|item["status"]=="unknown").count()})
}
fn matching(methods: &[Value], fields: &[Value]) -> Value {
    let all = methods.iter().chain(fields);
    json!({"exact_il_signature":all.clone().filter(|item|item["match"]["basis"]=="exact-il-signature").count(),"exact_signature":all.clone().filter(|item|item["match"]["basis"]=="exact-signature").count(),"structural_method_shape":0,"field_signature":all.clone().filter(|item|item["match"]["basis"]=="field-signature").count(),"ambiguous":all.clone().filter(|item|item["match"]["status"]=="ambiguous").count(),"unmatched":all.filter(|item|item["match"]["status"]=="unmatched").count()})
}
fn digest(value: &Value) -> Result<String, String> {
    canonical_json::digest(value).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::compare;
    use serde_json::{Value, json};

    #[test]
    fn compares_exact_members_and_preserves_side_local_tokens() {
        let side = |id: &str, token: &str| json!({"evidence_id":id,"operation":"inspect_managed_members","normalized_result":{"artifact":{"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"module":{"name":"m","mvid":null},"coverage":{"state":"complete"},"methods":[{"token":token,"declaring_type":"T","name":"M","signature":{"raw_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"body":{"il_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","normalized_il_sha256":null}}],"fields":[]}});
        let output = compare(
            &json!({"left":side("ev_left","0x06000001"),"right":side("ev_right","0x06000009")}),
        )
        .expect("comparison");
        assert_eq!(output["summary"]["unchanged"], 1);
        assert_eq!(output["methods"][0]["left"]["token"], "0x06000001");
        assert_eq!(output["methods"][0]["right"]["token"], "0x06000009");
    }

    #[test]
    fn reports_unique_added_and_removed_members() {
        let side = |id: &str, methods: Value| {
            json!({
                "evidence_id": id,
                "operation": "inspect_managed_members",
                "normalized_result": {
                    "artifact": {"sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
                    "module": {"name": "m", "mvid": null},
                    "metadata": {"status": "complete"},
                    "coverage": {"state": "complete"},
                    "methods": methods,
                    "fields": []
                }
            })
        };
        let output = compare(&json!({
            "left": side("ev_left", json!([{"token":"0x06000001","declaring_type":"T","name":"Old","signature":{"raw_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"body":{"normalized_il_sha256":null}}])),
            "right": side("ev_right", json!([{"token":"0x06000009","declaring_type":"T","name":"New","signature":{"raw_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"},"body":{"normalized_il_sha256":null}}]))
        }))
        .expect("comparison");

        assert_eq!(output["summary"]["removed"], 1);
        assert_eq!(output["summary"]["added"], 1);
        assert!(
            output["methods"]
                .as_array()
                .expect("methods")
                .iter()
                .all(|item| item["match"]["status"] == "unmatched")
        );
    }

    #[test]
    fn preserves_unknown_for_duplicate_keys() {
        let row = json!({
            "token":"0x06000001",
            "declaring_type":"T",
            "name":"M",
            "signature":{"raw_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
            "body":{"normalized_il_sha256":null}
        });
        let side = |id: &str| {
            json!({
                "evidence_id": id,
                "operation": "inspect_managed_members",
                "normalized_result": {
                    "artifact": {"sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
                    "module": {"name": "m", "mvid": null},
                    "metadata": {"status": "complete"},
                    "coverage": {"state": "complete"},
                    "methods": [row.clone(), row.clone()],
                    "fields": []
                }
            })
        };
        let output = compare(&json!({"left": side("ev_left"), "right": side("ev_right")}))
            .expect("comparison");

        assert_eq!(output["summary"]["unknown"], 1);
        assert_eq!(output["methods"][0]["match"]["status"], "ambiguous");
    }
}
