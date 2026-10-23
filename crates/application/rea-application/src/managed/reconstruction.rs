//! Authenticated import of managed decompiler reconstruction.

use rea_core::canonical_json;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub fn import_reconstruction(input: &Value) -> Result<Value, String> {
    validate_request_shape(input)?;
    let static_evidence = input
        .get("static_members")
        .ok_or("static_members is required")?;
    if static_evidence.get("operation").and_then(Value::as_str) != Some("inspect_managed_members") {
        return Err("Evidence operation is not inspect_managed_members".into());
    }
    let evidence_id = static_evidence
        .get("evidence_id")
        .and_then(Value::as_str)
        .ok_or("static Evidence has no evidence_id")?;
    let result = static_evidence
        .get("normalized_result")
        .or_else(|| static_evidence.get("result"))
        .ok_or("static Evidence has no normalized_result")?;
    let members = result.get("members").unwrap_or(result);
    let candidates = input
        .get("methods")
        .and_then(Value::as_array)
        .ok_or("methods must be an array")?;
    if candidates.is_empty() {
        return Err("methods must contain at least one method".into());
    }
    let observed = members
        .get("methods")
        .and_then(Value::as_array)
        .ok_or("static member Evidence has no methods")?;
    let mut methods = Vec::new();
    for candidate in candidates {
        let token = candidate
            .get("token")
            .and_then(Value::as_str)
            .ok_or("reconstruction method has no token")?;
        let signature = candidate
            .get("signature_sha256")
            .and_then(Value::as_str)
            .ok_or("reconstruction method has no signature_sha256")?;
        validate_token(token)?;
        validate_digest(signature, "signature_sha256")?;
        let normalized = candidate.get("normalized_il_sha256");
        if let Some(value) = normalized {
            if !value.is_null() {
                validate_digest(
                    value
                        .as_str()
                        .ok_or("normalized_il_sha256 must be a digest or null")?,
                    "normalized_il_sha256",
                )?;
            }
        } else {
            return Err("reconstruction method has no normalized_il_sha256".into());
        }
        let normalized = normalized.and_then(Value::as_str);
        let reconstruction = candidate
            .get("reconstruction")
            .ok_or("reconstruction method has no reconstruction payload")?;
        validate_reconstruction(reconstruction)?;
        let member = observed
            .iter()
            .find(|method| {
                method.get("token").and_then(Value::as_str) == Some(token)
                    && method
                        .pointer("/signature/raw_sha256")
                        .and_then(Value::as_str)
                        == Some(signature)
                    && method.pointer("/body/status").and_then(Value::as_str) == Some("present")
                    && method
                        .pointer("/body/normalized_il_sha256")
                        .and_then(Value::as_str)
                        == normalized
            })
            .ok_or_else(|| {
                format!("Reconstruction method lock {token} does not match static managed Evidence")
            })?;
        let text = reconstruction
            .get("text")
            .and_then(Value::as_str)
            .filter(|text| !text.is_empty())
            .ok_or("reconstruction text must be non-empty")?;
        let text_sha256 = sha256_text(text);
        if reconstruction
            .get("text_sha256")
            .and_then(Value::as_str)
            .is_some_and(|expected| expected != text_sha256)
        {
            return Err(format!("Reconstruction text hash mismatch for {token}"));
        }
        methods.push(json!({
            "token": token,
            "declaring_type": member.get("declaring_type").cloned().unwrap_or(Value::Null),
            "name": member.get("name").cloned().unwrap_or(Value::String(String::new())),
            "signature_sha256": signature,
            "normalized_il_sha256": normalized,
            "body_sha256": member.pointer("/body/il_sha256").cloned().unwrap_or(Value::Null),
            "il_size": member.pointer("/body/il_size").and_then(Value::as_u64).unwrap_or(0),
            "reconstruction": {
                "kind": reconstruction.get("kind").cloned().unwrap_or(Value::String("semantic-pseudocode".into())),
                "language": reconstruction.get("language").cloned().unwrap_or(Value::String("pseudocode".into())),
                "text": text,
                "text_sha256": text_sha256,
                "text_length": text.encode_utf16().count(),
                "line_count": count_lines(text),
                "source_path": reconstruction.get("source_path").cloned().unwrap_or(Value::Null),
                "start_line": reconstruction.get("start_line").cloned().unwrap_or(Value::Null),
                "end_line": reconstruction.get("end_line").cloned().unwrap_or(Value::Null)
            },
            "validation": {"matched_static_member":true,"exact_build_required":true,"canonical_observation":false,"confidence_floor":"inference"}
        }));
    }
    let artifact = result
        .get("artifact")
        .ok_or("static member Evidence has no artifact")?;
    let artifact_sha256 = artifact
        .get("sha256")
        .and_then(Value::as_str)
        .ok_or("static member Evidence artifact has no sha256")?;
    validate_digest(artifact_sha256, "artifact.sha256")?;
    let artifact_path = artifact
        .get("path")
        .and_then(Value::as_str)
        .filter(|path| !path.is_empty())
        .ok_or("static member Evidence artifact has no path")?;
    let byte_length = artifact
        .get("byte_length")
        .and_then(Value::as_u64)
        .ok_or("static member Evidence artifact has no byte_length")?;
    let module = members.get("module").or_else(|| result.get("module"));
    let decompiler = input
        .get("decompiler")
        .cloned()
        .ok_or("decompiler is required")?;
    validate_decompiler(&decompiler)?;
    let mut decompiler_out = decompiler.clone();
    if let Some(object) = decompiler_out.as_object_mut() {
        object.entry("version").or_insert_with(|| Value::Null);
        object
            .entry("executable_sha256")
            .or_insert_with(|| Value::Null);
        object.entry("options").or_insert_with(|| json!([]));
    }
    decompiler_out["options_sha256"] = Value::String(canonical_digest(
        decompiler.get("options").unwrap_or(&json!([])),
    )?);
    let summary = json!({"imported_methods":methods.len(),"decompiled_csharp_methods":methods.iter().filter(|item| item.pointer("/reconstruction/kind").and_then(Value::as_str)==Some("decompiled-csharp")).count(),"decompiled_il_methods":methods.iter().filter(|item| item.pointer("/reconstruction/kind").and_then(Value::as_str)==Some("decompiled-il")).count(),"pseudocode_methods":methods.iter().filter(|item| item.pointer("/reconstruction/kind").and_then(Value::as_str)==Some("semantic-pseudocode")).count(),"total_text_bytes":methods.iter().map(|item| item.pointer("/reconstruction/text").and_then(Value::as_str).map_or(0, |text| text.len())).sum::<usize>()});
    let without_id = json!({
        "phase":"reconstruction-import", "executed":false,
        "static_observation":{"evidence_id":evidence_id,"artifact_sha256":artifact_sha256,"artifact_path":artifact_path,"byte_length":byte_length,"module_name":module.and_then(|value| value.get("name")).cloned().unwrap_or(Value::Null),"mvid":module.and_then(|value| value.get("mvid")).cloned().unwrap_or(Value::Null),"metadata_status":members.pointer("/metadata/status").cloned().unwrap_or(json!("partial"))},
        "decompiler":decompiler_out,"summary":summary,"methods":methods,"notes":input.get("notes").cloned().unwrap_or(json!([])),"evidence_links":[evidence_id],"limitations":["Decompiler output is imported as reconstruction evidence and analyst inference; metadata and IL observations remain canonical.","This operation did not execute, load, reflect over, debug, instrument, patch, or decompile the target artifact.","The imported reconstruction is valid only for the exact artifact SHA-256, MVID, method signature, and normalized IL shape recorded here.","Obfuscated names, decompiler variables, and control-flow restructuring are not treated as proof without separate validation."]
    });
    let mut output = without_id;
    output["reconstruction_id"] = Value::String(format!("mre_{}", canonical_digest(&output)?));
    Ok(output)
}

fn sha256_text(text: &str) -> String {
    format!("{:x}", Sha256::digest(text.as_bytes()))
}

fn validate_request_shape(input: &Value) -> Result<(), String> {
    let object = input.as_object().ok_or("request must be an object")?;
    for field in ["static_members", "decompiler", "methods"] {
        if !object.contains_key(field) {
            return Err(format!("{field} is required"));
        }
    }
    if let Some(notes) = object.get("notes") {
        let values = notes.as_array().ok_or("notes must be an array")?;
        if values
            .iter()
            .any(|note| note.as_str().is_none_or(str::is_empty))
        {
            return Err("notes must contain non-empty strings".into());
        }
    }
    Ok(())
}

fn validate_token(token: &str) -> Result<(), String> {
    let valid = token.len() == 10
        && token.starts_with("0x")
        && token[2..]
            .chars()
            .all(|character| character.is_ascii_hexdigit())
        && token[2..]
            .chars()
            .all(|character| !character.is_ascii_uppercase());
    if valid {
        Ok(())
    } else {
        Err(format!("invalid managed metadata token: {token}"))
    }
}

fn validate_digest(value: &str, field: &str) -> Result<(), String> {
    let valid = value.len() == 64
        && value.chars().all(|character| character.is_ascii_hexdigit())
        && value
            .chars()
            .all(|character| !character.is_ascii_uppercase());
    if valid {
        Ok(())
    } else {
        Err(format!("{field} must be a lowercase SHA-256 digest"))
    }
}

fn validate_decompiler(decompiler: &Value) -> Result<(), String> {
    let object = decompiler
        .as_object()
        .ok_or("decompiler must be an object")?;
    if object
        .get("name")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err("decompiler.name must be non-empty".into());
    }
    let family = object
        .get("family")
        .and_then(Value::as_str)
        .ok_or("decompiler.family is required")?;
    if !matches!(family, "ilspy" | "dnspy" | "dnlib" | "mono-cecil" | "other") {
        return Err("decompiler.family is unsupported".into());
    }
    if let Some(version) = object.get("version") {
        if !version.is_null() && version.as_str().is_none() {
            return Err("decompiler.version must be a string or null".into());
        }
    }
    if let Some(digest) = object.get("executable_sha256") {
        if !digest.is_null() {
            validate_digest(
                digest
                    .as_str()
                    .ok_or("decompiler.executable_sha256 must be a digest or null")?,
                "decompiler.executable_sha256",
            )?;
        }
    }
    if let Some(options) = object.get("options") {
        let options = options
            .as_array()
            .ok_or("decompiler.options must be an array")?;
        if options.iter().any(|option| option.as_str().is_none()) {
            return Err("decompiler.options must contain strings".into());
        }
    }
    Ok(())
}

fn validate_reconstruction(reconstruction: &Value) -> Result<(), String> {
    let object = reconstruction
        .as_object()
        .ok_or("reconstruction must be an object")?;
    let kind = object
        .get("kind")
        .and_then(Value::as_str)
        .ok_or("reconstruction.kind is required")?;
    let language = object
        .get("language")
        .and_then(Value::as_str)
        .ok_or("reconstruction.language is required")?;
    let expected_language = match kind {
        "decompiled-csharp" => "csharp",
        "decompiled-il" => "il",
        "semantic-pseudocode" => "pseudocode",
        _ => return Err("reconstruction.kind is unsupported".into()),
    };
    if language != expected_language {
        return Err(format!(
            "reconstruction.language must be {expected_language} for {kind}"
        ));
    }
    if let Some(path) = object.get("source_path") {
        if !path.is_null() && path.as_str().is_none_or(str::is_empty) {
            return Err("reconstruction.source_path must be a non-empty string or null".into());
        }
    }
    for field in ["start_line", "end_line"] {
        if let Some(line) = object.get(field) {
            if !line.is_null() && line.as_u64().is_none_or(|value| value == 0) {
                return Err(format!(
                    "reconstruction.{field} must be a positive integer or null"
                ));
            }
        }
    }
    Ok(())
}

fn count_lines(text: &str) -> usize {
    if text.is_empty() {
        return 0;
    }

    let mut lines = 1;
    let mut characters = text.chars().peekable();
    while let Some(character) = characters.next() {
        if character == '\n' {
            lines += 1;
        } else if character == '\r' && characters.peek() != Some(&'\n') {
            lines += 1;
        }
    }
    lines
}

fn canonical_digest(value: &Value) -> Result<String, String> {
    canonical_json::digest(value).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::import_reconstruction;
    use serde_json::json;

    #[test]
    fn locks_reconstruction_to_exact_static_member_shape() {
        let output = import_reconstruction(&json!({
            "static_members":{"evidence_id":"ev_static","operation":"inspect_managed_members","normalized_result":{"artifact":{"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","path":"/tmp/a.dll","byte_length":12},"metadata":{"status":"complete"},"module":{"name":"a","mvid":null},"methods":[{"token":"0x06000001","declaring_type":"T","name":"M","signature":{"raw_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"body":{"status":"present","normalized_il_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","il_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","il_size":3}}]}},
            "decompiler":{"name":"ilspy","family":"ilspy","options":[]},
            "methods":[{"token":"0x06000001","signature_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","normalized_il_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","reconstruction":{"kind":"decompiled-csharp","language":"csharp","text":"return 1;"}}]
        })).expect("reconstruction");
        assert_eq!(output["summary"]["imported_methods"], 1);
        assert_eq!(
            output["methods"][0]["validation"]["exact_build_required"],
            true
        );
    }
}
