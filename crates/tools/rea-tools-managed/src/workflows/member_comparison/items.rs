//! Per-member comparison items: matched, ambiguous, and one-sided rows.
//!
//! Compatibility owner: `src/domain/managed/managedMemberComparisonItems.ts`.
use super::matching::{Ambiguous, Keyed, MatchedPair, Matches, sha256};
use super::signature::signature_identity;
use crate::workflows::error::DomainError;
use serde_json::{Value, json};
use std::collections::HashSet;

/// `ComparisonItemContext`.
pub struct ItemContext {
    pub left_evidence_id: String,
    pub right_evidence_id: String,
    pub left_complete: bool,
    pub right_complete: bool,
    /// Declaring types each side selected; `None` when every type was inspected.
    pub left_selection: Option<HashSet<String>>,
    pub right_selection: Option<HashSet<String>>,
    /// Whether matching keyed signatures by resolved digests, not raw bytes.
    pub signature_resolution_examined: bool,
}

impl ItemContext {
    fn evidence_links(&self) -> Value {
        json!([self.left_evidence_id, self.right_evidence_id])
    }
}

/// Side marker for a one-sided member.
#[derive(Clone, Copy, PartialEq)]
enum Side {
    Left,
    Right,
}

/// `inventoryCovers(complete, selection, member)`.
fn inventory_covers(complete: bool, selection: &Option<HashSet<String>>, member: &Value) -> bool {
    if !complete {
        return false;
    }
    match selection {
        None => true,
        Some(selection) => member
            .get("declaring_type")
            .and_then(Value::as_str)
            .map(|declaring_type| selection.contains(declaring_type))
            .unwrap_or(false),
    }
}

/// `UndecodedOneSidedNames`: declared names of unpaired members per side.
struct UndecodedOneSided {
    resolved: bool,
    undecoded_left: HashSet<String>,
    undecoded_right: HashSet<String>,
    unresolved_left: HashSet<String>,
    unresolved_right: HashSet<String>,
    unknown_owners_left: HashSet<String>,
    unknown_owners_right: HashSet<String>,
}

impl UndecodedOneSided {
    fn undecoded(&self, side: Side) -> &HashSet<String> {
        match side {
            Side::Left => &self.undecoded_left,
            Side::Right => &self.undecoded_right,
        }
    }

    fn unresolved(&self, side: Side) -> &HashSet<String> {
        match side {
            Side::Left => &self.unresolved_left,
            Side::Right => &self.unresolved_right,
        }
    }

    fn unknown_owners(&self, side: Side) -> &HashSet<String> {
        match side {
            Side::Left => &self.unknown_owners_left,
            Side::Right => &self.unknown_owners_right,
        }
    }
}

/// `undecodedOneSidedNames(members, resolved)`.
fn undecoded_one_sided(matches: &Matches, resolved: bool) -> UndecodedOneSided {
    let left: Vec<&Keyed> = matches
        .left_only
        .iter()
        .chain(matches.ambiguous.iter().flat_map(|group| group.left.iter()))
        .collect();
    let right: Vec<&Keyed> = matches
        .right_only
        .iter()
        .chain(
            matches
                .ambiguous
                .iter()
                .flat_map(|group| group.right.iter()),
        )
        .collect();

    let undecoded = |member: &Keyed| signature_parse_status(&member.item) != "decoded";
    let not_resolved = |member: &Keyed| unresolved_member(&member.item, resolved);

    let names = |side: &[&Keyed], keep: &dyn Fn(&Keyed) -> bool| -> HashSet<String> {
        side.iter()
            .filter(|member| keep(member))
            .map(|member| member.identity.clone())
            .collect()
    };
    let owners = |side: &[&Keyed]| -> HashSet<String> {
        side.iter()
            .filter(|member| member.identity_unavailable)
            .map(|member| member.name().to_owned())
            .collect()
    };

    UndecodedOneSided {
        resolved,
        unknown_owners_left: owners(&left),
        unknown_owners_right: owners(&right),
        undecoded_left: names(&left, &undecoded),
        undecoded_right: names(&right, &undecoded),
        unresolved_left: names(&left, &not_resolved),
        unresolved_right: names(&right, &not_resolved),
    }
}

fn signature_parse_status(member: &Value) -> &str {
    member
        .get("signature")
        .and_then(|signature| signature.get("parse_status"))
        .and_then(Value::as_str)
        .unwrap_or_default()
}

/// `unresolved(member, resolved)`: a known signature form whose type operands
/// still compare by raw bytes.
fn unresolved_member(member: &Value, resolved: bool) -> bool {
    if !resolved {
        return false;
    }
    let signature = member.get("signature");
    let kind = signature
        .and_then(|signature| signature.get("kind"))
        .and_then(Value::as_str);
    let resolved_sha256 = signature
        .and_then(|signature| signature.get("resolved_sha256"))
        .map(Value::is_null)
        .unwrap_or(true);
    kind != Some("unknown") && resolved_sha256
}

/// `methodIdentity(item)`.
fn method_identity(item: &Value) -> Value {
    json!({
        "token": item.get("token").cloned().unwrap_or(Value::Null),
        "declaring_type": item.get("declaring_type").cloned().unwrap_or(Value::Null),
        "name": item.get("name").cloned().unwrap_or(Value::Null),
        "signature_sha256": item
            .get("signature")
            .and_then(|signature| signature.get("raw_sha256"))
            .cloned()
            .unwrap_or(Value::Null),
        "normalized_il_sha256": item
            .get("body")
            .and_then(|body| body.get("normalized_il_sha256"))
            .cloned()
            .unwrap_or(Value::Null),
    })
}

/// `fieldIdentity(item)`.
fn field_identity(item: &Value) -> Value {
    json!({
        "token": item.get("token").cloned().unwrap_or(Value::Null),
        "declaring_type": item.get("declaring_type").cloned().unwrap_or(Value::Null),
        "name": item.get("name").cloned().unwrap_or(Value::Null),
        "signature_sha256": item
            .get("signature")
            .and_then(|signature| signature.get("raw_sha256"))
            .cloned()
            .unwrap_or(Value::Null),
    })
}

/// `unmatchedComparison()`.
fn unmatched_comparison() -> Value {
    json!({
        "status": "unmatched",
        "basis": "none",
        "confidence": "unknown",
        "candidate_left_tokens": [],
        "candidate_right_tokens": [],
    })
}

/// RFC 8785 canonical digest of a value, for shape equality comparisons.
///
/// The TS comparisons test `canonicalize(a) !== canonicalize(b)`; comparing
/// canonical digests is equivalent for equality and avoids materializing the
/// serialized form.
fn canonical(value: &Value) -> Result<String, DomainError> {
    rea_core::canonical_json::digest(value)
        .map_err(|_| DomainError::type_error("Managed comparison canonicalization failed"))
}

/// `callShape(anchors)`: `JSON.stringify` of `[opcode, operand_kind]` for method
/// operands.
fn call_shape(anchors: &Value) -> String {
    anchor_shape(anchors, "method")
}

/// `fieldShape(anchors)`.
fn field_shape(anchors: &Value) -> String {
    anchor_shape(anchors, "field")
}

fn anchor_shape(anchors: &Value, operand_kind: &str) -> String {
    let projected: Vec<Value> = anchors
        .as_array()
        .map(|anchors| {
            anchors
                .iter()
                .filter(|anchor| {
                    anchor.get("operand_kind").and_then(Value::as_str) == Some(operand_kind)
                })
                .map(|anchor| {
                    json!([
                        anchor.get("opcode").cloned().unwrap_or(Value::Null),
                        anchor.get("operand_kind").cloned().unwrap_or(Value::Null)
                    ])
                })
                .collect()
        })
        .unwrap_or_default();
    Value::Array(projected).to_string()
}

/// A method body's `status` string, if present.
fn body_status(body: &Value) -> Option<&str> {
    body.get("status").and_then(Value::as_str)
}

/// `methodDimensions(left, right)`.
fn method_dimensions(
    left: &Value,
    right: &Value,
) -> Result<(Vec<&'static str>, bool), DomainError> {
    let mut dimensions: Vec<&'static str> = Vec::new();
    let left_body = left.get("body").cloned().unwrap_or(Value::Null);
    let right_body = right.get("body").cloned().unwrap_or(Value::Null);

    if left.get("flags") != right.get("flags") || left.get("impl_flags") != right.get("impl_flags")
    {
        dimensions.push("metadata");
    }
    if signature_identity(&left.get("signature").cloned().unwrap_or(Value::Null))
        != signature_identity(&right.get("signature").cloned().unwrap_or(Value::Null))
    {
        dimensions.push("signature");
    }

    let truncated_zero =
        |body: &Value| body.get("truncated_instructions").and_then(Value::as_i64) == Some(0);
    let left_body_complete =
        body_status(&left_body) == Some("present") && truncated_zero(&left_body);
    let right_body_complete =
        body_status(&right_body) == Some("present") && truncated_zero(&right_body);
    let both_absent =
        body_status(&left_body) == Some("absent") && body_status(&right_body) == Some("absent");

    if (body_status(&left_body) == Some("absent") && right_body_complete)
        || (body_status(&right_body) == Some("absent") && left_body_complete)
    {
        dimensions.push("availability");
    }
    if both_absent {
        return Ok((dimensions, false));
    }
    if !left_body_complete || !right_body_complete {
        return Ok((dimensions, true));
    }

    if left_body.get("il_sha256") != right_body.get("il_sha256")
        || left_body.get("normalized_il_sha256") != right_body.get("normalized_il_sha256")
    {
        dimensions.push("cil");
    }
    if canonical(left_body.get("opcode_counts").unwrap_or(&Value::Null))?
        != canonical(right_body.get("opcode_counts").unwrap_or(&Value::Null))?
    {
        dimensions.push("opcode-shape");
    }
    let left_anchors = left_body.get("anchors").cloned().unwrap_or(Value::Null);
    let right_anchors = right_body.get("anchors").cloned().unwrap_or(Value::Null);
    if call_shape(&left_anchors) != call_shape(&right_anchors) {
        dimensions.push("call-shape");
    }
    if field_shape(&left_anchors) != field_shape(&right_anchors) {
        dimensions.push("field-shape");
    }
    if canonical(left_body.get("exception_regions").unwrap_or(&Value::Null))?
        != canonical(right_body.get("exception_regions").unwrap_or(&Value::Null))?
    {
        dimensions.push("exception-shape");
    }
    Ok((dimensions, false))
}

/// `absenceLimitations(member, identity, opposite)`.
#[allow(clippy::too_many_arguments)]
fn absence_limitations(
    member: &Value,
    identity: &str,
    opposite_complete: bool,
    own_identity_unavailable: bool,
    unpaired: &UndecodedOneSided,
    opposite: Side,
    inventory: &str,
) -> Vec<String> {
    let opposite_word = match opposite {
        Side::Left => "left",
        Side::Right => "right",
    };
    let mut limitations: Vec<String> = Vec::new();
    if own_identity_unavailable {
        limitations.push(
            "declaring-type-name-not-resolved: Declared type identity could not be resolved; a bare display name cannot establish a counterpart or absence."
                .to_owned(),
        );
    }
    let member_name = member
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if unpaired.unknown_owners(opposite).contains(member_name) {
        limitations.push(format!(
            "counterpart-declaring-type-name-not-resolved: The {opposite_word} {inventory} inventory has an unpaired same-named member with unresolved enclosing-name identity, so absence was not established."
        ));
    }
    if !opposite_complete {
        limitations.push(format!(
            "unknown-within-incomplete-metadata: The {opposite_word} {inventory} inventory is incomplete, so absence was not observed."
        ));
    }
    let parse_status = signature_parse_status(member);
    if parse_status != "decoded" {
        limitations.push(format!(
            "signature-not-decoded: The member's {parse_status} signature was compared only by exact declared type, name, and signature bytes, so a changed or renamed counterpart could not be sought."
        ));
    }
    if parse_status == "decoded" && unpaired.undecoded(opposite).contains(identity) {
        limitations.push(format!(
            "counterpart-signature-not-decoded: The {opposite_word} {inventory} inventory has an unpaired member with the same declared type and name whose signature was not decoded, so it may be this member with a changed signature."
        ));
    }
    let member_unresolved = unresolved_member(member, unpaired.resolved);
    if member_unresolved {
        limitations.push(
            "signature-not-resolved: The member's signature names a type REA could not name, so it was compared by raw bytes, which name types by build-local metadata row; a counterpart whose referenced type moved rows could not be found."
                .to_owned(),
        );
    }
    if parse_status == "decoded"
        && !member_unresolved
        && unpaired.unresolved(opposite).contains(identity)
    {
        limitations.push(format!(
            "counterpart-signature-not-resolved: The {opposite_word} {inventory} inventory has an unpaired member with the same declared type and name whose signature names a type REA could not name, so it may be this member."
        ));
    }
    limitations
}

/// `pairedSignatureLimitations(left, right, examined)`.
fn paired_signature_limitations(left: &Value, right: &Value, examined: bool) -> Vec<String> {
    if unresolved_member(left, examined) || unresolved_member(right, examined) {
        vec![
            "signature-not-resolved: At least one signature names a type REA could not resolve; equal build-local row bytes do not establish equivalent signature types."
                .to_owned(),
        ]
    } else {
        Vec::new()
    }
}

/// `ambiguityLimitation(members, basis, identityUnavailable)`.
fn ambiguity_limitation(members: &str, basis: &str, identity_unavailable: bool) -> String {
    if identity_unavailable {
        "declaring-type-name-not-resolved: Declared type identity remains unresolved; REA did not guess a counterpart from display names, signatures or CIL.".to_owned()
    } else if basis == "exact-signature" {
        format!(
            "Multiple managed {members} share the same signature; REA did not guess declared ownership or a token remap."
        )
    } else if basis == "exact-il-signature" {
        "Multiple managed methods share the same CIL and signature; REA did not guess a token remap.".to_owned()
    } else if members == "methods" {
        "Multiple managed methods share the same structural shape; REA did not guess a token remap."
            .to_owned()
    } else {
        "Multiple managed fields share the same signature; REA did not guess a token remap."
            .to_owned()
    }
}

fn ambiguity_identity_unavailable(group: &Ambiguous) -> bool {
    group.left.iter().any(|item| item.identity_unavailable)
        || group.right.iter().any(|item| item.identity_unavailable)
}

fn tokens(members: &[Keyed]) -> Value {
    Value::Array(members.iter().map(|member| json!(member.token())).collect())
}

/// `methodOnlyItem(member, identity, identityUnavailable, context, undecoded)`.
fn method_only_item(
    member: &Keyed,
    side: Side,
    context: &ItemContext,
    undecoded: &UndecodedOneSided,
) -> Result<Value, DomainError> {
    let item = &member.item;
    let (opposite, opposite_complete, left_value, right_value) = match side {
        Side::Left => (
            Side::Right,
            inventory_covers(context.right_complete, &context.right_selection, item),
            method_identity(item),
            Value::Null,
        ),
        Side::Right => (
            Side::Left,
            inventory_covers(context.left_complete, &context.left_selection, item),
            Value::Null,
            method_identity(item),
        ),
    };
    let limitations = absence_limitations(
        item,
        &member.identity,
        opposite_complete,
        member.identity_unavailable,
        undecoded,
        opposite,
        "method",
    );
    let status = if limitations.is_empty() {
        match side {
            Side::Left => "removed",
            Side::Right => "added",
        }
    } else {
        "unknown"
    };
    let side_label = match side {
        Side::Left => "left",
        Side::Right => "right",
    };
    let item_id = format!(
        "mmc_method_{}",
        sha256(&json!({ "token": member.token(), "side": side_label }))?
    );
    Ok(json!({
        "item_id": item_id,
        "status": status,
        "left": left_value,
        "right": right_value,
        "match": unmatched_comparison(),
        "dimensions": ["availability"],
        "evidence_links": context.evidence_links(),
        "limitations": limitations,
    }))
}

/// `fieldOnlyItem(...)`.
fn field_only_item(
    member: &Keyed,
    side: Side,
    context: &ItemContext,
    undecoded: &UndecodedOneSided,
) -> Result<Value, DomainError> {
    let item = &member.item;
    let (opposite, opposite_complete, left_value, right_value) = match side {
        Side::Left => (
            Side::Right,
            inventory_covers(context.right_complete, &context.right_selection, item),
            field_identity(item),
            Value::Null,
        ),
        Side::Right => (
            Side::Left,
            inventory_covers(context.left_complete, &context.left_selection, item),
            Value::Null,
            field_identity(item),
        ),
    };
    let limitations = absence_limitations(
        item,
        &member.identity,
        opposite_complete,
        member.identity_unavailable,
        undecoded,
        opposite,
        "field",
    );
    let status = if limitations.is_empty() {
        match side {
            Side::Left => "removed",
            Side::Right => "added",
        }
    } else {
        "unknown"
    };
    let side_label = match side {
        Side::Left => "left",
        Side::Right => "right",
    };
    let item_id = format!(
        "mmc_field_{}",
        sha256(&json!({ "token": member.token(), "side": side_label }))?
    );
    Ok(json!({
        "item_id": item_id,
        "status": status,
        "left": left_value,
        "right": right_value,
        "match": unmatched_comparison(),
        "evidence_links": context.evidence_links(),
        "limitations": limitations,
    }))
}

/// `buildMethodItems(matches, context)`.
pub fn build_method_items(
    matches: &Matches,
    context: &ItemContext,
) -> Result<Vec<Value>, DomainError> {
    let mut items: Vec<Value> = Vec::new();
    for pair in &matches.pairs {
        items.push(method_pair_item(pair, context)?);
    }
    for ambiguous in &matches.ambiguous {
        items.push(method_ambiguous_item(ambiguous, context)?);
    }
    let undecoded = undecoded_one_sided(matches, context.signature_resolution_examined);
    for member in &matches.left_only {
        items.push(method_only_item(member, Side::Left, context, &undecoded)?);
    }
    for member in &matches.right_only {
        items.push(method_only_item(member, Side::Right, context, &undecoded)?);
    }
    Ok(items)
}

fn method_pair_item(pair: &MatchedPair, context: &ItemContext) -> Result<Value, DomainError> {
    let signature_limitations = paired_signature_limitations(
        &pair.left.item,
        &pair.right.item,
        context.signature_resolution_examined,
    );
    let (observed_dimensions, body_unknown) = method_dimensions(&pair.left.item, &pair.right.item)?;
    let mut dimensions: Vec<&str> = observed_dimensions.clone();
    if body_unknown {
        dimensions.push("body-coverage");
    }
    let observed_change = !observed_dimensions.is_empty();
    let status = if observed_change {
        "changed"
    } else if body_unknown || !signature_limitations.is_empty() {
        "unknown"
    } else {
        "unchanged"
    };
    let item_id = format!(
        "mmc_method_{}",
        sha256(&json!({
            "left": pair.left.token(),
            "right": pair.right.token(),
            "basis": pair.basis,
        }))?
    );
    let mut limitations = signature_limitations;
    if body_unknown {
        limitations.push(
            "Method body facets are unknown because at least one side has unavailable or partial body data."
                .to_owned(),
        );
    }
    Ok(json!({
        "item_id": item_id,
        "status": status,
        "left": method_identity(&pair.left.item),
        "right": method_identity(&pair.right.item),
        "match": {
            "status": "matched",
            "basis": pair.basis,
            "confidence": pair.confidence,
            "candidate_left_tokens": [],
            "candidate_right_tokens": [],
        },
        "dimensions": dimensions,
        "evidence_links": context.evidence_links(),
        "limitations": limitations,
    }))
}

fn method_ambiguous_item(
    ambiguous: &Ambiguous,
    context: &ItemContext,
) -> Result<Value, DomainError> {
    let item_id = format!(
        "mmc_method_{}",
        sha256(&json!({
            "left": token_list(&ambiguous.left),
            "right": token_list(&ambiguous.right),
            "basis": ambiguous.basis,
        }))?
    );
    Ok(json!({
        "item_id": item_id,
        "status": "unknown",
        "left": Value::Null,
        "right": Value::Null,
        "match": {
            "status": "ambiguous",
            "basis": ambiguous.basis,
            "confidence": "unknown",
            "candidate_left_tokens": tokens(&ambiguous.left),
            "candidate_right_tokens": tokens(&ambiguous.right),
        },
        "dimensions": ["availability"],
        "evidence_links": context.evidence_links(),
        "limitations": [ambiguity_limitation("methods", ambiguous.basis, ambiguity_identity_unavailable(ambiguous))],
    }))
}

/// `buildFieldItems(matches, context)`.
pub fn build_field_items(
    matches: &Matches,
    context: &ItemContext,
) -> Result<Vec<Value>, DomainError> {
    let mut items: Vec<Value> = Vec::new();
    for pair in &matches.pairs {
        items.push(field_pair_item(pair, context)?);
    }
    for ambiguous in &matches.ambiguous {
        items.push(field_ambiguous_item(ambiguous, context)?);
    }
    let undecoded = undecoded_one_sided(matches, context.signature_resolution_examined);
    for member in &matches.left_only {
        items.push(field_only_item(member, Side::Left, context, &undecoded)?);
    }
    for member in &matches.right_only {
        items.push(field_only_item(member, Side::Right, context, &undecoded)?);
    }
    Ok(items)
}

fn field_pair_item(pair: &MatchedPair, context: &ItemContext) -> Result<Value, DomainError> {
    let signature_limitations = paired_signature_limitations(
        &pair.left.item,
        &pair.right.item,
        context.signature_resolution_examined,
    );
    let changed = signature_identity(
        &pair
            .left
            .item
            .get("signature")
            .cloned()
            .unwrap_or(Value::Null),
    ) != signature_identity(
        &pair
            .right
            .item
            .get("signature")
            .cloned()
            .unwrap_or(Value::Null),
    ) || pair.left.item.get("flags") != pair.right.item.get("flags");
    let status = if changed {
        "changed"
    } else if !signature_limitations.is_empty() {
        "unknown"
    } else {
        "unchanged"
    };
    let item_id = format!(
        "mmc_field_{}",
        sha256(&json!({
            "left": pair.left.token(),
            "right": pair.right.token(),
        }))?
    );
    Ok(json!({
        "item_id": item_id,
        "status": status,
        "left": field_identity(&pair.left.item),
        "right": field_identity(&pair.right.item),
        "match": {
            "status": "matched",
            "basis": pair.basis,
            "confidence": pair.confidence,
            "candidate_left_tokens": [],
            "candidate_right_tokens": [],
        },
        "evidence_links": context.evidence_links(),
        "limitations": signature_limitations,
    }))
}

fn field_ambiguous_item(
    ambiguous: &Ambiguous,
    context: &ItemContext,
) -> Result<Value, DomainError> {
    let item_id = format!(
        "mmc_field_{}",
        sha256(&json!({
            "left": token_list(&ambiguous.left),
            "right": token_list(&ambiguous.right),
        }))?
    );
    Ok(json!({
        "item_id": item_id,
        "status": "unknown",
        "left": Value::Null,
        "right": Value::Null,
        "match": {
            "status": "ambiguous",
            "basis": ambiguous.basis,
            "confidence": "unknown",
            "candidate_left_tokens": tokens(&ambiguous.left),
            "candidate_right_tokens": tokens(&ambiguous.right),
        },
        "evidence_links": context.evidence_links(),
        "limitations": [ambiguity_limitation("fields", ambiguous.basis, ambiguity_identity_unavailable(ambiguous))],
    }))
}

/// Tokens of an ambiguous group's members, as a `Vec<&str>` for hashing.
fn token_list(members: &[Keyed]) -> Vec<String> {
    members
        .iter()
        .map(|member| member.token().to_owned())
        .collect()
}
