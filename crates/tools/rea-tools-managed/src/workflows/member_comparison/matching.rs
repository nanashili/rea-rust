//! Obfuscation-resistant member matching across two managed observations.
//!
//! Compatibility owner: `src/domain/managed/managedMemberComparisonMatch.ts`.
use super::signature::{comparable_sides, signature_identity};
use crate::workflows::error::DomainError;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};

/// `sha256(canonicalize(value))`: RFC 8785 canonical digest, lowercase hex.
pub fn sha256(value: &Value) -> Result<String, DomainError> {
    rea_core::canonical_json::digest(value)
        .map_err(|_| DomainError::type_error("Managed comparison canonicalization failed"))
}

/// One keyed member: its source row and the keys each matching round reads.
#[derive(Clone)]
pub struct Keyed {
    /// The source member row (`methods`/`fields` element).
    pub item: Value,
    /// Declared type and name digest; the name remains when the type is null.
    pub identity: String,
    /// Declared identity could not be resolved; display facts remain.
    pub identity_unavailable: bool,
    pub exact_key: Option<String>,
    pub signature_key: Option<String>,
    /// The name-free exact signature, resolved where both sides resolve it.
    pub signature_id: String,
    pub structural_key: Option<String>,
}

impl Keyed {
    pub fn token(&self) -> &str {
        self.item
            .get("token")
            .and_then(Value::as_str)
            .unwrap_or_default()
    }

    pub fn name(&self) -> &str {
        self.item
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default()
    }
}

/// `MatchedPair`.
pub struct MatchedPair {
    pub left: Keyed,
    pub right: Keyed,
    pub basis: &'static str,
    pub confidence: &'static str,
}

/// `Ambiguous`.
pub struct Ambiguous {
    pub left: Vec<Keyed>,
    pub right: Vec<Keyed>,
    pub basis: &'static str,
}

/// The result of one `matchByKeys` call.
pub struct Matches {
    pub pairs: Vec<MatchedPair>,
    pub ambiguous: Vec<Ambiguous>,
    pub left_only: Vec<Keyed>,
    pub right_only: Vec<Keyed>,
}

/// A declared type: a historical bare name, a tagged observed nominal digest,
/// or null. Modeled as a JSON `Value` so it hashes exactly like TS.
type DeclaredName = Value;

/// `identityOf({ declaring_type, name })`: `sha256([declaring_type, name])`.
fn identity_of(declaring_type: &DeclaredName, name: &str) -> Result<String, DomainError> {
    sha256(&json!([declaring_type, name]))
}

/// Round selector: a round's primary key and its competition key.
struct Round {
    basis: &'static str,
    key: KeyKind,
    /// Name-free evidence paired with the retained member name for contesting.
    /// `None` falls back to `exact_key`, matching the TS default.
    competition: Option<CompetitionKind>,
    remap: bool,
}

/// Which selected key a round groups by.
#[derive(Clone, Copy)]
enum KeyKind {
    /// `declaredAs(({ exactKey }) => exactKey)`.
    DeclaredExact,
    /// `({ signatureKey }) => signatureKey`.
    Signature,
    /// `declaredAs(keyed => keyed.identityUnavailable ? null : keyed.structuralKey)`.
    DeclaredStructural,
    /// `({ exactKey }) => exactKey`.
    Exact,
    /// `({ structuralKey }) => structuralKey`.
    Structural,
}

/// Which name-free evidence key a round contests by.
#[derive(Clone, Copy)]
enum CompetitionKind {
    SignatureId,
    Structural,
}

impl KeyKind {
    fn key(self, item: &Keyed) -> Result<Option<String>, DomainError> {
        match self {
            KeyKind::DeclaredExact => declared_as(item, item.exact_key.clone()),
            KeyKind::Signature => Ok(item.signature_key.clone()),
            KeyKind::DeclaredStructural => {
                let value = if item.identity_unavailable {
                    None
                } else {
                    item.structural_key.clone()
                };
                declared_as(item, value)
            }
            KeyKind::Exact => Ok(item.exact_key.clone()),
            KeyKind::Structural => Ok(item.structural_key.clone()),
        }
    }
}

impl CompetitionKind {
    fn key(self, item: &Keyed) -> Option<String> {
        match self {
            CompetitionKind::SignatureId => Some(item.signature_id.clone()),
            CompetitionKind::Structural => item.structural_key.clone(),
        }
    }
}

/// `declaredAs(key)`: narrow a key to members of one declared type and name.
fn declared_as(item: &Keyed, value: Option<String>) -> Result<Option<String>, DomainError> {
    match value {
        None => Ok(None),
        Some(_) if item.identity_unavailable => Ok(None),
        Some(value) => Ok(Some(sha256(&json!([item.identity, value]))?)),
    }
}

/// `competitionKey ?? (item => item.exactKey)`.
fn competition_key(round: &Round, item: &Keyed) -> Option<String> {
    match round.competition {
        Some(kind) => kind.key(item),
        None => item.exact_key.clone(),
    }
}

/// `competitionIdentityKey(member, evidenceKey)`:
/// `JSON.stringify([member.item.name, evidenceKey])` or null.
fn competition_identity_key(member: &Keyed, evidence_key: Option<&str>) -> Option<String> {
    evidence_key.map(|key| {
        // `JSON.stringify([name, key])` — a two-element array of strings.
        Value::Array(vec![json!(member.name()), json!(key)]).to_string()
    })
}

/// `ownerlessContested(sides, keyOf)`.
fn ownerless_contested(
    sides: &[&[Keyed]],
    key_of: impl Fn(&Keyed) -> Option<String>,
) -> HashSet<String> {
    let mut contested = HashSet::new();
    for side in sides {
        let mut seen: HashMap<String, u32> = HashMap::new();
        let mut ownerless: HashSet<String> = HashSet::new();
        for member in side.iter() {
            let evidence = key_of(member);
            let Some(key) = competition_identity_key(member, evidence.as_deref()) else {
                continue;
            };
            *seen.entry(key.clone()).or_insert(0) += 1;
            if member.identity_unavailable {
                ownerless.insert(key);
            }
        }
        for key in ownerless {
            if seen.get(&key).copied().unwrap_or(0) > 1 {
                contested.insert(key);
            }
        }
    }
    contested
}

/// `declaredCandidates(left, right, keyOf)`: predicate over a member.
fn declared_candidate(
    member: &Keyed,
    key_of: impl Fn(&Keyed) -> Option<String>,
    contested: &HashSet<String>,
) -> bool {
    if member.identity_unavailable {
        return false;
    }
    let key = competition_identity_key(member, key_of(member).as_deref());
    match key {
        None => true,
        Some(key) => !contested.contains(&key),
    }
}

/// `remappable(items, others, keyOf, contested)`.
fn remappable(
    items: &[Keyed],
    others: &[Keyed],
    key_of: impl Fn(&Keyed) -> Option<String>,
    contested: &HashSet<String>,
) -> Vec<Keyed> {
    let kept: HashSet<&str> = others.iter().map(|item| item.identity.as_str()).collect();
    items
        .iter()
        .filter(|member| {
            let key = key_of(member);
            (key.is_some()
                && contested.contains(
                    &competition_identity_key(member, key.as_deref()).unwrap_or_default(),
                ))
                || member.identity_unavailable
                || !kept.contains(member.identity.as_str())
        })
        .cloned()
        .collect()
}

/// `groupBy(items, keyOf)` preserving first-seen key order.
fn group_by(
    items: &[Keyed],
    key_of: impl Fn(&Keyed) -> Result<Option<String>, DomainError>,
) -> Result<Vec<(String, Vec<Keyed>)>, DomainError> {
    let mut order: Vec<String> = Vec::new();
    let mut groups: HashMap<String, Vec<Keyed>> = HashMap::new();
    for item in items {
        let Some(key) = key_of(item)? else { continue };
        if !groups.contains_key(&key) {
            order.push(key.clone());
        }
        groups.entry(key).or_default().push(item.clone());
    }
    Ok(order
        .into_iter()
        .map(|key| {
            let bucket = groups.remove(&key).unwrap_or_default();
            (key, bucket)
        })
        .collect())
}

/// `matchByKeys({ left, right, rounds })`.
fn match_by_keys(
    left: &[Keyed],
    right: &[Keyed],
    rounds: &[Round],
) -> Result<Matches, DomainError> {
    let mut used_left: HashSet<usize> = HashSet::new();
    let mut used_right: HashSet<usize> = HashSet::new();
    let mut paired_left: HashSet<usize> = HashSet::new();
    let mut paired_right: HashSet<usize> = HashSet::new();
    let mut pairs: Vec<MatchedPair> = Vec::new();
    let mut ambiguous: Vec<Ambiguous> = Vec::new();

    for round in rounds {
        let comp = |item: &Keyed| competition_key(round, item);

        let unpaired_left = indexed_filter(left, &paired_left);
        let unpaired_right = indexed_filter(right, &paired_right);
        let declarable_contested = ownerless_contested(&[&unpaired_left, &unpaired_right], comp);

        let open_left = indexed_filter(left, &used_left);
        let open_right = indexed_filter(right, &used_right);

        let remap_contested = if round.remap {
            ownerless_contested(&[&open_left, &open_right], comp)
        } else {
            HashSet::new()
        };

        let left_candidates = if round.remap {
            remappable(&open_left, &unpaired_right, comp, &remap_contested)
        } else {
            open_left
                .iter()
                .filter(|item| declared_candidate(item, comp, &declarable_contested))
                .cloned()
                .collect()
        };
        let right_candidates = if round.remap {
            remappable(&open_right, &unpaired_left, comp, &remap_contested)
        } else {
            open_right
                .iter()
                .filter(|item| declared_candidate(item, comp, &declarable_contested))
                .cloned()
                .collect()
        };

        let left_groups = group_by(&left_candidates, |item| round.key.key(item))?;
        let mut right_groups = group_by(&right_candidates, |item| round.key.key(item))?;
        let right_map: HashMap<String, Vec<Keyed>> = right_groups.drain(..).collect();

        for (key, left_items) in left_groups {
            let Some(right_items) = right_map.get(&key) else {
                continue;
            };
            // An unresolved owner may be either member's own counterpart, so a
            // remap group it joins stays ambiguous.
            let refused = round.remap
                && left_items
                    .iter()
                    .chain(right_items.iter())
                    .any(|item| item.identity_unavailable);
            if !refused && left_items.len() == 1 && right_items.len() == 1 {
                let left_item = left_items[0].clone();
                let right_item = right_items[0].clone();
                mark(&mut used_left, left, &left_item);
                mark(&mut used_right, right, &right_item);
                mark(&mut paired_left, left, &left_item);
                mark(&mut paired_right, right, &right_item);
                let confidence = match round.basis {
                    "exact-il-signature" | "exact-signature" | "field-signature" => "exact",
                    _ => "high",
                };
                pairs.push(MatchedPair {
                    left: left_item,
                    right: right_item,
                    basis: round.basis,
                    confidence,
                });
            } else {
                for item in &left_items {
                    mark(&mut used_left, left, item);
                }
                for item in right_items {
                    mark(&mut used_right, right, item);
                }
                ambiguous.push(Ambiguous {
                    left: left_items,
                    right: right_items.clone(),
                    basis: round.basis,
                });
            }
        }
    }

    // Unresolved signature ambiguities over open candidates.
    let open_left = indexed_filter(left, &used_left);
    let open_right = indexed_filter(right, &used_right);
    let unpaired_left = indexed_filter(left, &paired_left);
    let unpaired_right = indexed_filter(right, &paired_right);
    let signature_contested = ownerless_contested(&[&unpaired_left, &unpaired_right], |member| {
        Some(member.signature_id.clone())
    });
    for group in unresolved_signature_ambiguities(&open_left, &open_right, &signature_contested) {
        for item in &group.left {
            mark(&mut used_left, left, item);
        }
        for item in &group.right {
            mark(&mut used_right, right, item);
        }
        ambiguous.push(group);
    }

    Ok(Matches {
        pairs,
        ambiguous,
        left_only: indexed_filter(left, &used_left),
        right_only: indexed_filter(right, &used_right),
    })
}

/// `unresolvedSignatureAmbiguities(left, right, contested)`.
fn unresolved_signature_ambiguities(
    left: &[Keyed],
    right: &[Keyed],
    contested: &HashSet<String>,
) -> Vec<Ambiguous> {
    let key = |member: &Keyed| -> Option<String> {
        Some(
            competition_identity_key(member, Some(member.signature_id.as_str()))
                .unwrap_or_default(),
        )
    };
    let left_groups = group_by_infallible(left, &key);
    let right_map: HashMap<String, Vec<Keyed>> =
        group_by_infallible(right, &key).into_iter().collect();
    let mut groups = Vec::new();
    for (signature, left_items) in left_groups {
        let Some(right_items) = right_map.get(&signature) else {
            continue;
        };
        if !contested.contains(&signature) {
            continue;
        }
        groups.push(Ambiguous {
            left: left_items,
            right: right_items.clone(),
            basis: "exact-signature",
        });
    }
    groups
}

/// A `groupBy` whose key function never fails.
fn group_by_infallible(
    items: &[Keyed],
    key_of: &impl Fn(&Keyed) -> Option<String>,
) -> Vec<(String, Vec<Keyed>)> {
    let mut order: Vec<String> = Vec::new();
    let mut groups: HashMap<String, Vec<Keyed>> = HashMap::new();
    for item in items {
        let Some(key) = key_of(item) else { continue };
        if !groups.contains_key(&key) {
            order.push(key.clone());
        }
        groups.entry(key).or_default().push(item.clone());
    }
    order
        .into_iter()
        .map(|key| {
            let bucket = groups.remove(&key).unwrap_or_default();
            (key, bucket)
        })
        .collect()
}

/// Members of `all` whose index is not present in `excluded`, order preserved.
fn indexed_filter(all: &[Keyed], excluded: &HashSet<usize>) -> Vec<Keyed> {
    all.iter()
        .enumerate()
        .filter(|(index, _)| !excluded.contains(index))
        .map(|(_, item)| item.clone())
        .collect()
}

/// Record the index of `target` within `all` (object-identity set membership).
fn mark(set: &mut HashSet<usize>, all: &[Keyed], target: &Keyed) {
    if let Some(index) = index_of(all, target) {
        set.insert(index);
    }
}

/// The index of a keyed member within its originating side.
///
/// TS tracks membership by object identity. Each side's members are distinct
/// rows, so the unique (token, name, identity) triple identifies one row.
fn index_of(all: &[Keyed], target: &Keyed) -> Option<usize> {
    all.iter().position(|item| {
        item.token() == target.token()
            && item.name() == target.name()
            && item.identity == target.identity
            && item.signature_id == target.signature_id
    })
}

/// `keyMethod(item, declared)`.
fn key_method(item: &Value, declared: &DeclaredName) -> Result<Keyed, DomainError> {
    let name = item.get("name").and_then(Value::as_str).unwrap_or_default();
    let signature = item.get("signature").cloned().unwrap_or(Value::Null);
    let signature_id = signature_identity(&signature);
    let body = item.get("body").cloned().unwrap_or(Value::Null);
    let body_status = body.get("status").and_then(Value::as_str);
    let il_sha256 = body.get("il_sha256").cloned().unwrap_or(Value::Null);
    let normalized_il = body
        .get("normalized_il_sha256")
        .cloned()
        .unwrap_or(Value::Null);

    let exact_key =
        if body_status == Some("present") && !il_sha256.is_null() && !normalized_il.is_null() {
            Some(sha256(&json!([
                "method-exact",
                signature_id,
                il_sha256,
                normalized_il
            ]))?)
        } else {
            None
        };

    let signature_key = if declared.is_null() {
        None
    } else {
        Some(sha256(&json!([
            "method-signature",
            declared,
            name,
            signature_id
        ]))?)
    };

    let parse_status = signature.get("parse_status").and_then(Value::as_str);
    let structural_key = if parse_status == Some("decoded") && body_status == Some("present") {
        let anchors = body
            .get("anchors")
            .and_then(Value::as_array)
            .map(|anchors| {
                anchors
                    .iter()
                    .map(|anchor| {
                        let opcode = anchor.get("opcode").cloned().unwrap_or(Value::Null);
                        let operand_kind =
                            anchor.get("operand_kind").cloned().unwrap_or(Value::Null);
                        let operand = if anchor.get("operand_kind").and_then(Value::as_str)
                            == Some("constant")
                        {
                            anchor.get("operand").cloned().unwrap_or(Value::Null)
                        } else {
                            Value::Null
                        };
                        json!([opcode, operand_kind, operand])
                    })
                    .collect::<Vec<Value>>()
            })
            .unwrap_or_default();
        let regions = body
            .get("exception_regions")
            .and_then(Value::as_array)
            .map(|regions| {
                regions
                    .iter()
                    .map(|region| {
                        let flags = region.get("flags").cloned().unwrap_or(Value::Null);
                        let try_length = region.get("try_length").cloned().unwrap_or(Value::Null);
                        let handler_length =
                            region.get("handler_length").cloned().unwrap_or(Value::Null);
                        let class_token =
                            if region.get("class_token").map(Value::is_null) != Some(false) {
                                Value::Null
                            } else {
                                json!("type-token")
                            };
                        let filter =
                            if region.get("filter_offset").map(Value::is_null) != Some(false) {
                                Value::Null
                            } else {
                                json!("filter")
                            };
                        json!([flags, try_length, handler_length, class_token, filter])
                    })
                    .collect::<Vec<Value>>()
            })
            .unwrap_or_default();
        Some(sha256(&json!([
            "method-structural",
            signature_id,
            body.get("status").cloned().unwrap_or(Value::Null),
            body.get("header_format").cloned().unwrap_or(Value::Null),
            body.get("il_size").cloned().unwrap_or(Value::Null),
            body.get("max_stack").cloned().unwrap_or(Value::Null),
            body.get("init_locals").cloned().unwrap_or(Value::Null),
            body.get("opcode_counts").cloned().unwrap_or(Value::Null),
            Value::Array(anchors),
            Value::Array(regions),
        ]))?)
    } else {
        None
    };

    Ok(Keyed {
        item: item.clone(),
        identity: identity_of(declared, name)?,
        identity_unavailable: declared.is_null(),
        exact_key,
        signature_key,
        signature_id,
        structural_key,
    })
}

/// `keyField(item, declared)`.
fn key_field(item: &Value, declared: &DeclaredName) -> Result<Keyed, DomainError> {
    let name = item.get("name").and_then(Value::as_str).unwrap_or_default();
    let signature = item.get("signature").cloned().unwrap_or(Value::Null);
    let signature_id = signature_identity(&signature);
    let parse_status = signature.get("parse_status").and_then(Value::as_str);

    let exact_key = if parse_status == Some("decoded") {
        Some(sha256(&json!(["field-exact", signature_id]))?)
    } else {
        None
    };

    let signature_key = if declared.is_null() {
        None
    } else {
        Some(sha256(&json!([
            "field-signature",
            declared,
            name,
            signature_id
        ]))?)
    };

    let structural_key = Some(sha256(&json!([
        "field-structural",
        signature.get("kind").cloned().unwrap_or(Value::Null),
        signature.get("field_type").cloned().unwrap_or(Value::Null),
        item.get("flags").cloned().unwrap_or(Value::Null),
    ]))?);

    Ok(Keyed {
        item: item.clone(),
        identity: identity_of(declared, name)?,
        identity_unavailable: declared.is_null(),
        exact_key,
        signature_key,
        signature_id,
        structural_key,
    })
}

fn method_rounds() -> Vec<Round> {
    vec![
        Round {
            basis: "exact-il-signature",
            key: KeyKind::DeclaredExact,
            competition: None,
            remap: false,
        },
        Round {
            basis: "exact-signature",
            key: KeyKind::Signature,
            competition: Some(CompetitionKind::SignatureId),
            remap: false,
        },
        Round {
            basis: "structural-method-shape",
            key: KeyKind::DeclaredStructural,
            competition: Some(CompetitionKind::Structural),
            remap: false,
        },
        Round {
            basis: "exact-il-signature",
            key: KeyKind::Exact,
            competition: None,
            remap: true,
        },
        Round {
            basis: "structural-method-shape",
            key: KeyKind::Structural,
            competition: Some(CompetitionKind::Structural),
            remap: true,
        },
    ]
}

fn field_rounds() -> Vec<Round> {
    vec![
        Round {
            basis: "field-signature",
            key: KeyKind::DeclaredExact,
            competition: None,
            remap: false,
        },
        Round {
            basis: "exact-signature",
            key: KeyKind::Signature,
            competition: Some(CompetitionKind::SignatureId),
            remap: false,
        },
        Round {
            basis: "field-signature",
            key: KeyKind::Exact,
            competition: None,
            remap: true,
        },
    ]
}

/// `observedBy(side)`: whether a side's inventory observed this declaring type.
fn observed_by(result: &Value, declaring_type: Option<&str>) -> bool {
    match result.get("selection") {
        Some(selection) if !selection.is_null() => {
            let Some(declaring_type) = declaring_type else {
                return false;
            };
            selection
                .get("type_names")
                .and_then(Value::as_array)
                .map(|names| {
                    names
                        .iter()
                        .any(|name| name.as_str() == Some(declaring_type))
                })
                .unwrap_or(false)
        }
        _ => true,
    }
}

type DeclaredResolver<'resolver> = dyn Fn(&Value) -> DeclaredName + 'resolver;

/// `declared(inspection)`: resolve a member's declared type name.
fn declared_resolver<'resolver>(
    inspection: &'resolver Value,
    modern: bool,
) -> Box<DeclaredResolver<'resolver>> {
    let nesting_read = inspection
        .get("nesting_read")
        .cloned()
        .unwrap_or(Value::Null);
    let names: HashMap<String, Value> = inspection
        .get("types")
        .and_then(Value::as_array)
        .map(|types| {
            types
                .iter()
                .filter_map(|type_row| {
                    let token = type_row.get("token").and_then(Value::as_str)?.to_owned();
                    let name_sha256 = type_row.get("name_sha256").cloned().unwrap_or(Value::Null);
                    Some((token, name_sha256))
                })
                .collect()
        })
        .unwrap_or_default();
    Box::new(move |item: &Value| -> DeclaredName {
        // `inspection.nesting_read === false` → null.
        if nesting_read.as_bool() == Some(false) {
            return Value::Null;
        }
        let token = item
            .get("declaring_type_token")
            .and_then(Value::as_str)
            .unwrap_or("");
        let digest = names.get(token);
        let digest_missing = matches!(digest, None | Some(Value::Null));
        // A historical counterpart cannot repair an observed current name gap.
        if !nesting_read.is_null() && digest_missing {
            return Value::Null;
        }
        // Historical observations retain their bare-name mode.
        if !modern {
            return item.get("declaring_type").cloned().unwrap_or(Value::Null);
        }
        match digest {
            Some(digest) if !digest.is_null() => json!(["nominal-name-sha256", digest]),
            _ => Value::Null,
        }
    })
}

/// `matchObserved(...)`: pair only members both sides observed; append the
/// one-sided remainder to the respective `*_only` list.
#[allow(clippy::too_many_arguments)]
fn match_observed(
    left_members: &[Value],
    right_members: &[Value],
    left_result: &Value,
    right_result: &Value,
    key_left: &impl Fn(&Value) -> Result<Keyed, DomainError>,
    key_right: &impl Fn(&Value) -> Result<Keyed, DomainError>,
    rounds: &[Round],
) -> Result<Matches, DomainError> {
    let in_left = |item: &Value| {
        observed_by(
            left_result,
            item.get("declaring_type").and_then(Value::as_str),
        )
    };
    let in_right = |item: &Value| {
        observed_by(
            right_result,
            item.get("declaring_type").and_then(Value::as_str),
        )
    };

    let left_keyed: Vec<Keyed> = left_members
        .iter()
        .filter(|item| in_right(item))
        .map(|item| key_left(item))
        .collect::<Result<_, _>>()?;
    let right_keyed: Vec<Keyed> = right_members
        .iter()
        .filter(|item| in_left(item))
        .map(|item| key_right(item))
        .collect::<Result<_, _>>()?;

    let mut matched = match_by_keys(&left_keyed, &right_keyed, rounds)?;

    for item in left_members.iter().filter(|item| !in_right(item)) {
        matched.left_only.push(key_left(item)?);
    }
    for item in right_members.iter().filter(|item| !in_left(item)) {
        matched.right_only.push(key_right(item)?);
    }
    Ok(matched)
}

/// `keyMembers(observedLeft, observedRight)`.
pub struct MemberMatches {
    pub method_matches: Matches,
    pub field_matches: Matches,
}

pub fn key_members(
    observed_left: &Value,
    observed_right: &Value,
) -> Result<MemberMatches, DomainError> {
    let (left, right) = comparable_sides(observed_left, observed_right);
    let modern = !left.get("nesting_read").map(Value::is_null).unwrap_or(true)
        && !right
            .get("nesting_read")
            .map(Value::is_null)
            .unwrap_or(true);
    let declared_left = declared_resolver(&left, modern);
    let declared_right = declared_resolver(&right, modern);

    let empty: Vec<Value> = Vec::new();
    let left_methods = left
        .get("methods")
        .and_then(Value::as_array)
        .unwrap_or(&empty);
    let right_methods = right
        .get("methods")
        .and_then(Value::as_array)
        .unwrap_or(&empty);
    let left_fields = left
        .get("fields")
        .and_then(Value::as_array)
        .unwrap_or(&empty);
    let right_fields = right
        .get("fields")
        .and_then(Value::as_array)
        .unwrap_or(&empty);

    let method_matches = match_observed(
        left_methods,
        right_methods,
        &left,
        &right,
        &|item| key_method(item, &declared_left(item)),
        &|item| key_method(item, &declared_right(item)),
        &method_rounds(),
    )?;
    let field_matches = match_observed(
        left_fields,
        right_fields,
        &left,
        &right,
        &|item| key_field(item, &declared_left(item)),
        &|item| key_field(item, &declared_right(item)),
        &field_rounds(),
    )?;

    Ok(MemberMatches {
        method_matches,
        field_matches,
    })
}
