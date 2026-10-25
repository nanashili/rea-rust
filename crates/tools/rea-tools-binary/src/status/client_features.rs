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
