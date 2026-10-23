//! Signature identity and comparable-side normalization.
//!
//! Compatibility owner:
//! `src/domain/managed/managedMemberSignatureIdentity.ts`.
use serde_json::Value;

/// `signatureIdentity({ raw_sha256, resolved_sha256 })`.
///
/// The exact signature across builds: raw bytes with type operands resolved to
/// names. The kind is part of the key: `raw:` when unresolved, `resolved:`
/// otherwise.
pub fn signature_identity(signature: &Value) -> String {
    let raw = signature
        .get("raw_sha256")
        .and_then(Value::as_str)
        .unwrap_or_default();
    match signature.get("resolved_sha256").and_then(Value::as_str) {
        None => format!("raw:{raw}"),
        Some(resolved) => format!("resolved:{resolved}"),
    }
}

/// `hasSignatureResolution(result)`: the producer attests examination
/// independently of whether it could resolve any operands. A current inventory
/// of only unresolved types is not legacy.
pub fn has_signature_resolution(result: &Value) -> bool {
    let attested = result
        .get("signature_resolution")
        .map(|value| !value.is_null())
        .unwrap_or(false);
    if attested {
        return true;
    }
    let methods_empty = result
        .get("methods")
        .and_then(Value::as_array)
        .map(|items| items.is_empty())
        .unwrap_or(true);
    let fields_empty = result
        .get("fields")
        .and_then(Value::as_array)
        .map(|items| items.is_empty())
        .unwrap_or(true);
    methods_empty && fields_empty
}

/// `comparableSides(left, right)`: compare raw signatures on both sides when
/// either observation predates resolved digests.
///
/// Returns the (possibly rewritten) left and right inspection results. When
/// both sides attest resolution the inputs are returned unchanged; otherwise
/// both sides have every method and field signature `resolved_sha256` forced to
/// null so they compare by raw bytes.
pub fn comparable_sides(left: &Value, right: &Value) -> (Value, Value) {
    if has_signature_resolution(left) && has_signature_resolution(right) {
        return (left.clone(), right.clone());
    }
    (without_resolution(left), without_resolution(right))
}

/// `{ ...side.result, methods: withoutResolution, fields: withoutResolution }`.
fn without_resolution(result: &Value) -> Value {
    let mut object = result.as_object().cloned().unwrap_or_default();
    strip_members(&mut object, "methods");
    strip_members(&mut object, "fields");
    Value::Object(object)
}

/// `withoutResolution(members)`: each member's signature keeps its value except
/// `resolved_sha256`, which becomes null.
fn strip_members(object: &mut serde_json::Map<String, Value>, key: &str) {
    if let Some(Value::Array(members)) = object.get_mut(key) {
        for member in members {
            if let Value::Object(member_object) = member
                && let Some(Value::Object(signature)) = member_object.get_mut("signature")
            {
                signature.insert("resolved_sha256".to_owned(), Value::Null);
            }
        }
    }
}
