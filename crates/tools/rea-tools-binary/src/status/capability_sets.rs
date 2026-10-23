//! `providerCapabilitySets` from `src/application/binary/BinarySessionStatus.ts`.
//!
//! Groups a provider's capability descriptors into the wire
//! `ProviderCapabilitySet` shape (`src/contracts/toolOutputSchemaPrimitives.ts`),
//! preserving provider identity, shared-limitation prefixes and the frozen
//! `PROVIDER_EFFECT_NAMES` effect order.

use rea_analysis::CapabilityDescriptor;
use serde_json::{Map, Value, json};

/// `PROVIDER_EFFECT_NAMES` order, derived from
/// `providerCapabilityFacts.effects.shape` in
/// `src/contracts/toolOutputSchemaPrimitives.ts`.
const PROVIDER_EFFECT_NAMES: [(&str, fn(&rea_analysis::CapabilityEffects) -> bool); 7] = [
    ("mutates_artifact", |effects| effects.mutates_artifact),
    ("launches_process", |effects| effects.launches_process),
    ("may_show_ui", |effects| effects.may_show_ui),
    ("may_access_network", |effects| effects.may_access_network),
    ("may_write_filesystem", |effects| {
        effects.may_write_filesystem
    }),
    ("changes_permissions", |effects| effects.changes_permissions),
    ("requires_root", |effects| effects.requires_root),
];

fn provider_summary(provider: &rea_analysis::ProviderIdentity) -> Value {
    json!({
        "id": provider.id,
        "name": provider.name,
        "version": provider.version,
    })
}

/// `enabledCapabilityEffects`: the subset of `PROVIDER_EFFECT_NAMES` whose
/// effect flag is set, in frozen order.
fn enabled_capability_effects(effects: &rea_analysis::CapabilityEffects) -> Vec<&'static str> {
    PROVIDER_EFFECT_NAMES
        .iter()
        .filter(|(_, read)| read(effects))
        .map(|(name, _)| *name)
        .collect()
}

/// `commonLimitationsPrefix`: the longest shared prefix of every descriptor's
/// limitation list (order-sensitive), from the first descriptor onward.
fn common_limitations_prefix(descriptors: &[&CapabilityDescriptor]) -> Vec<String> {
    let Some(first) = descriptors.first() else {
        return Vec::new();
    };
    let first = &first.limitations;
    let mut length = first.len();
    for descriptor in &descriptors[1..] {
        length = length.min(descriptor.limitations.len());
        let mut index = 0;
        while index < length && first[index] == descriptor.limitations[index] {
            index += 1;
        }
        length = index;
    }
    first[..length].to_vec()
}

/// The `available`/`reason`/`availability_code` projection for one descriptor.
///
/// An available descriptor reports `reason: null, availability_code: null`.
/// An unavailable descriptor whose reason is absent projects `reason: null`
/// (TS consumes a `CapabilityProjection` whose `reason` is `string | null`).
fn descriptor_status(descriptor: &CapabilityDescriptor) -> (bool, Value, Value) {
    if descriptor.available {
        (true, Value::Null, Value::Null)
    } else {
        let reason = descriptor
            .reason
            .as_ref()
            .map_or(Value::Null, |reason| Value::String(reason.clone()));
        let availability_code = descriptor
            .availability_code
            .as_ref()
            .map_or(Value::Null, |code| Value::String(code.clone()));
        (false, reason, availability_code)
    }
}

/// Project provider descriptors into the wire `ProviderCapabilitySet[]`.
///
/// Callers filter (`inventory_artifact` removed), sort by Unicode code points,
/// and apply runtime unavailability exactly as `binarySessionStatus` does
/// before invoking this projection.
pub(crate) fn provider_capability_sets(descriptors: &[CapabilityDescriptor]) -> Value {
    // Preserve first-seen provider order while grouping by identity.
    let mut provider_order: Vec<String> = Vec::new();
    let mut by_provider: std::collections::HashMap<String, Vec<&CapabilityDescriptor>> =
        std::collections::HashMap::new();
    for descriptor in descriptors {
        let key = provider_identity_key(&descriptor.provider);
        if !by_provider.contains_key(&key) {
            provider_order.push(key.clone());
        }
        by_provider.entry(key).or_default().push(descriptor);
    }

    let mut sets: Vec<Value> = Vec::with_capacity(provider_order.len());
    for key in &provider_order {
        let owned = &by_provider[key];
        let shared_limitations = common_limitations_prefix(owned);
        let shared_len = shared_limitations.len();

        // Preserve first-seen group order while merging operations.
        let mut group_order: Vec<String> = Vec::new();
        let mut groups: std::collections::HashMap<String, Value> = std::collections::HashMap::new();

        for descriptor in owned {
            let effects = enabled_capability_effects(&descriptor.effects);
            let limitations: Vec<String> = descriptor.limitations[shared_len..].to_vec();
            let (available, reason, availability_code) = descriptor_status(descriptor);

            // `key = JSON.stringify([effects, limitations, available, reason,
            // availability_code])` — a value-faithful grouping key.
            let group_key = serde_json::to_string(&json!([
                effects,
                limitations,
                available,
                reason,
                availability_code
            ]))
            .expect("group key is serializable");

            if let Some(group) = groups.get_mut(&group_key) {
                group["operations"]
                    .as_array_mut()
                    .expect("operations is an array")
                    .push(Value::String(descriptor.operation.clone()));
            } else {
                let mut group = Map::new();
                group.insert(
                    "operations".to_owned(),
                    Value::Array(vec![Value::String(descriptor.operation.clone())]),
                );
                group.insert(
                    "effects".to_owned(),
                    Value::Array(
                        effects
                            .iter()
                            .map(|name| Value::String((*name).to_owned()))
                            .collect(),
                    ),
                );
                group.insert(
                    "limitations".to_owned(),
                    Value::Array(limitations.into_iter().map(Value::String).collect()),
                );
                group.insert("available".to_owned(), Value::Bool(available));
                group.insert("reason".to_owned(), reason);
                group.insert("availability_code".to_owned(), availability_code);
                group_order.push(group_key.clone());
                groups.insert(group_key, Value::Object(group));
            }
        }

        let group_values: Vec<Value> = group_order
            .iter()
            .map(|key| groups.remove(key).expect("group present"))
            .collect();

        sets.push(json!({
            "provider": provider_summary(&owned[0].provider),
            "shared_limitations": shared_limitations,
            "groups": group_values,
        }));
    }

    Value::Array(sets)
}

/// `JSON.stringify([id, name, version])` provider grouping key, value-faithful.
fn provider_identity_key(provider: &rea_analysis::ProviderIdentity) -> String {
    serde_json::to_string(&json!([provider.id, provider.name, provider.version]))
        .expect("provider key is serializable")
}
