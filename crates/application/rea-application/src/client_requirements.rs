//! Read-only projection of negotiated MCP client features.
//!
//! Tool requirements belong to the application layer because they describe
//! how a workflow is exposed to a caller.  This module deliberately does not
//! probe, install, or otherwise modify the client.  It only compares the
//! caller's declared features with the requirements owned by the workflow.

use serde::{Deserialize, Serialize};

/// MCP client features that can affect workflow availability.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientFeature {
    ElicitationForm,
    ElicitationUrl,
    Roots,
    Sampling,
}

/// Negotiated MCP client features supplied by the caller.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClientFeatureAvailability {
    pub elicitation_form: bool,
    pub elicitation_url: bool,
    pub roots: bool,
    pub sampling: bool,
}

/// Empty client feature declaration used when the caller supplies none.
pub const NO_CLIENT_FEATURES: ClientFeatureAvailability = ClientFeatureAvailability {
    elicitation_form: false,
    elicitation_url: false,
    roots: false,
    sampling: false,
};

/// A tool's declared client requirements and the features currently missing.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClientRequirements {
    pub required: Vec<ClientFeature>,
    pub optional: Vec<ClientFeature>,
    pub missing_required: Vec<ClientFeature>,
    pub missing_optional: Vec<ClientFeature>,
}

/// Project a tool's requirements against the caller's negotiated features.
///
/// Requirements are currently empty for every native workflow.  Keeping the
/// comparison here gives future workflow owners one place to declare them and
/// preserves the same result shape for every caller.
pub fn client_requirements_for(
    _name: &str,
    client_features: ClientFeatureAvailability,
) -> ClientRequirements {
    let required = Vec::new();
    let optional = Vec::new();

    ClientRequirements {
        missing_required: missing_features(&required, client_features),
        missing_optional: missing_features(&optional, client_features),
        required,
        optional,
    }
}

fn missing_features(
    requirements: &[ClientFeature],
    client_features: ClientFeatureAvailability,
) -> Vec<ClientFeature> {
    requirements
        .iter()
        .copied()
        .filter(|feature| !client_features.supports(*feature))
        .collect()
}

impl ClientFeatureAvailability {
    fn supports(self, feature: ClientFeature) -> bool {
        match feature {
            ClientFeature::ElicitationForm => self.elicitation_form,
            ClientFeature::ElicitationUrl => self.elicitation_url,
            ClientFeature::Roots => self.roots,
            ClientFeature::Sampling => self.sampling,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ClientRequirements, NO_CLIENT_FEATURES, client_requirements_for};

    #[test]
    fn default_projection_preserves_empty_requirements() {
        assert_eq!(
            client_requirements_for("binary_overview", NO_CLIENT_FEATURES),
            ClientRequirements::default(),
        );
    }
}
