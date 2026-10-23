//! Negotiated MCP client features (`capabilityFeatures` in
//! `src/server/mcpClientMetadata.ts`) and their JSON projection
//! (`clientFeatureAvailabilitySchema` in
//! `src/contracts/toolOutputSchemaPrimitives.ts`).

use serde_json::{Value, json};

/// Negotiated MCP client features that affect REA workflow availability.
///
/// Mirrors TS `ClientFeatureAvailability` / `NO_CLIENT_FEATURES`.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ClientFeatures {
    pub elicitation_form: bool,
    pub elicitation_url: bool,
    pub roots: bool,
    pub sampling: bool,
}

impl ClientFeatures {
    /// `clientFeatureAvailabilitySchema` object projection, key order preserved.
    pub(crate) fn to_json(&self) -> Value {
        json!({
            "elicitation_form": self.elicitation_form,
            "elicitation_url": self.elicitation_url,
            "roots": self.roots,
            "sampling": self.sampling,
        })
    }
}

/// `capabilityFeatures` from `src/server/mcpClientMetadata.ts`.
///
/// `capabilities` is the raw negotiated client capabilities object (the value
/// the SDK stores for `CLIENT_CAPABILITIES_META_KEY`). A non-object is treated
/// as an empty capabilities set, exactly like the TS `isRecord` guard.
pub(crate) fn client_features_from_capabilities(capabilities: Option<&Value>) -> ClientFeatures {
    let capabilities = capabilities.and_then(Value::as_object);
    let elicitation = capabilities
        .and_then(|capabilities| capabilities.get("elicitation"))
        .and_then(Value::as_object);
    ClientFeatures {
        // A declared capability without modes retains the protocol's form-only
        // compatibility rule; a missing capability still grants no support.
        elicitation_form: elicitation.is_some_and(|elicitation| {
            elicitation.contains_key("form") || !elicitation.contains_key("url")
        }),
        elicitation_url: elicitation.is_some_and(|elicitation| elicitation.contains_key("url")),
        roots: capabilities.is_some_and(|capabilities| capabilities.contains_key("roots")),
        sampling: capabilities.is_some_and(|capabilities| capabilities.contains_key("sampling")),
    }
}
