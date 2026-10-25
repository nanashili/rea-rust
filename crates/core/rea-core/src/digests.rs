//! Source-owned identifier contracts omitted by the JSON Schema projection.

/// A source digest contract whose custom issue message is not representable in
/// the advertised JSON Schema dialect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrefixedDigestContract {
    /// The exact projected pattern owned by this contract.
    pub pattern: &'static str,
    /// The source validation message for a rejected value.
    pub invalid_message: &'static str,
}

/// Evidence identifiers use the shared `ev_` prefixed digest contract.
pub const EVIDENCE_ID: PrefixedDigestContract = PrefixedDigestContract {
    pattern: "^ev_[a-f0-9]{64}$",
    invalid_message: "Expected a ev_ prefixed lowercase sha256 digest",
};

/// Unknown-value identifiers use the shared `unk_` prefixed digest contract.
pub const UNKNOWN_ID: PrefixedDigestContract = PrefixedDigestContract {
    pattern: "^unk_[a-f0-9]{64}$",
    invalid_message: "Expected a unk_ prefixed lowercase sha256 digest",
};

/// JavaScript semantic graph nodes use the `jsrg_node_` prefixed digest contract.
pub const JS_RUNTIME_GRAPH_NODE_ID: PrefixedDigestContract = PrefixedDigestContract {
    pattern: "^jsrg_node_[a-f0-9]{64}$",
    invalid_message: "Expected a jsrg_node_ prefixed lowercase sha256 digest",
};
