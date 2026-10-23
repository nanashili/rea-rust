//! Shared caller-facing failure envelope for migrated application workflows.
use serde::Serialize;
use serde_json::value::RawValue;
use std::collections::BTreeMap;
use std::fmt::{self, Display, Formatter};

/// Named JSON details, including losslessly serialized partial observations.
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum Detail {
    /// Text fact.
    Text(String),
    /// Nonnegative admitted count.
    Count(u64),
    /// Explicit flag.
    Flag(bool),
    /// Ordered correction issues.
    Issues(Vec<InputIssue>),
    /// Ordered resource names.
    Texts(Vec<String>),
    /// Nested named facts.
    Fields(BTreeMap<&'static str, Detail>),
    /// Complete lossless serialized observation.
    Raw(Box<RawValue>),
}
/// Caller correction with identity kept separate from display formatting.
#[derive(Debug, Serialize)]
pub struct InputIssue {
    /// Argument components.
    pub path: Vec<String>,
    /// Stable correction classification.
    pub reason: &'static str,
    /// Concrete correction guidance.
    pub message: String,
    /// Optional concrete correction expected at this argument location.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected: Option<&'static str>,
}
#[derive(Debug, Serialize)]
struct Remediation {
    action: String,
}
/// Transport-neutral failure projection; CLI and MCP share this exact shape.
#[derive(Debug, Serialize)]
pub struct Failure {
    code: &'static str,
    category: &'static str,
    message: String,
    retryable: bool,
    remediation: Remediation,
    details: BTreeMap<String, Detail>,
}
impl Failure {
    /// Bind the canonical fields for an operation-specific tagged failure.
    pub fn new(
        code: &'static str,
        category: &'static str,
        message: String,
        retryable: bool,
        action: String,
        details: BTreeMap<&'static str, Detail>,
    ) -> Self {
        Self {
            code,
            category,
            message,
            retryable,
            remediation: Remediation { action },
            details: details
                .into_iter()
                .map(|(name, value)| (name.to_owned(), value))
                .collect(),
        }
    }

    /// Construct a failure with caller-defined detail keys.
    ///
    /// Most failures use the stable static keys accepted by [`Failure::new`].
    /// Workflows that retain source-defined names use this constructor so those
    /// names remain available without leaking them or narrowing them to a
    /// static-key set.
    pub fn new_with_details(
        code: &'static str,
        category: &'static str,
        message: String,
        retryable: bool,
        action: String,
        details: BTreeMap<String, Detail>,
    ) -> Self {
        Self {
            code,
            category,
            message,
            retryable,
            remediation: Remediation { action },
            details,
        }
    }

    /// Add an owned diagnostic without replacing the primary reason.
    pub fn detail(&mut self, name: &'static str, value: Detail) {
        self.details.insert(name.to_owned(), value);
    }
    /// Stable code used for CLI exit status and MCP isError.
    pub fn code(&self) -> &str {
        self.code
    }
    /// Named operation already interpreted by the failure's producing boundary.
    pub fn operation(&self) -> Option<&str> {
        match self.details.get("operation") {
            Some(Detail::Text(value)) => Some(value),
            _ => None,
        }
    }
    /// Retain completed observations without narrowing JSON text semantics.
    ///
    /// # Errors
    /// Returns a serialization error rather than dropping completed facts.
    pub fn retain<T: Serialize + ?Sized>(
        &mut self,
        observation: &T,
    ) -> Result<(), serde_json::Error> {
        self.detail(
            "partial_observation",
            Detail::Raw(serde_json::value::to_raw_value(observation)?),
        );
        Ok(())
    }
}

impl Display for Failure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for Failure {}

#[cfg(test)]
mod tests {
    use super::{Detail, Failure};
    use std::collections::BTreeMap;

    #[test]
    fn dynamic_detail_keys_survive_failure_serialization() {
        let failure = Failure::new_with_details(
            "invalid_request",
            "invalid_input",
            "A caller-selected limit is invalid.".into(),
            false,
            "Correct the supplied limit.".into(),
            BTreeMap::from([
                ("operation".into(), Detail::Text("inspect_image".into())),
                ("limits.max_sections".into(), Detail::Count(32)),
            ]),
        );

        let encoded = serde_json::to_value(&failure).unwrap();

        assert_eq!(failure.operation(), Some("inspect_image"));
        assert_eq!(encoded["details"]["limits.max_sections"], 32);
    }

    #[test]
    fn failure_display_uses_the_caller_facing_message() {
        let failure = Failure::new(
            "unavailable",
            "provider",
            "The selected provider is unavailable.".into(),
            true,
            "Retry when the provider is ready.".into(),
            BTreeMap::new(),
        );

        assert_eq!(failure.to_string(), "The selected provider is unavailable.");
    }
}
