//! Environment values that may cross a managed MCP registration boundary.
//!
//! Setup receives an explicit environment snapshot from its caller.  This
//! module owns the admission rule for that snapshot so registration code does
//! not accidentally copy the process environment (or credentials) into a
//! client configuration file.

use std::collections::{BTreeMap, BTreeSet};

/// Settings selected by setup itself.  Defaults are intentionally omitted:
/// the child REA process owns defaulting and can therefore distinguish an
/// omitted setting from a caller-selected value.
pub const EXPLICIT_SETUP_SETTINGS: &[&str] = &[
    "REA_ANALYSIS_PROVIDER",
    "REA_GHIDRA_RUST_TIMEOUT_MS",
    "REA_HOPPER_STARTUP_TIMEOUT_MS",
    "REA_JEB_MCP_TIMEOUT_MS",
    "REA_MCP_INPUT_SCHEMA_PROFILE",
];

/// Provider values currently published by the built-in adapters.  This is
/// metadata for diagnostics and review; provider values are still preserved
/// when an adapter publishes a newer or provider-specific key.
pub const PROVIDER_SETTINGS: &[&str] = &[
    "REA_GHIDRA_RUST_CACHE_DIR",
    "REA_GHIDRA_RUST_WORKER",
    "REA_IDA_MCP_CONFIG",
    "REA_JADX_ACTIVE_PROCESSOR_COUNT",
    "REA_JADX_HEAP_MIB",
    "REA_JADX_MCP_JAR",
    "REA_JADX_OPERATION_TIMEOUT_MS",
    "REA_JEB_MCP_URL",
    "REA_KUNA_CACHE_DIR",
    "REA_KUNA_CACHE_MAX_BYTES",
    "REA_KUNA_COMMAND",
    "REA_KUNA_JOBS",
    "REA_KUNA_PROJECT_TIMEOUT_MS",
    "REA_KUNA_TIMEOUT_MS",
];

/// Result of admitting explicit setup/provider values.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RegistrationEnvironment {
    /// Values safe to put in a client registration, in stable key order.
    pub values: BTreeMap<String, String>,
    /// Names outside the current catalog. Values are retained when they come
    /// from a validated provider inspection, but never when they come from an
    /// ambient setup snapshot.
    pub unknown_keys: BTreeSet<String>,
}

impl RegistrationEnvironment {
    /// Whether no caller-selected values were admitted.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

/// Preserve only setup-owned settings from an explicit environment snapshot.
pub fn explicit_setup_registration_environment(
    environment: &BTreeMap<String, String>,
) -> RegistrationEnvironment {
    admit(environment, EXPLICIT_SETUP_SETTINGS)
}

/// Merge provider-published values while retaining unknown names as metadata.
/// Provider inspections are already validated by their producing adapter, so
/// every published value is preserved. Later entries win deterministically,
/// matching the composition order used by the TypeScript setup host.
pub fn provider_registration_environment(
    inspections: &[BTreeMap<String, String>],
) -> RegistrationEnvironment {
    let mut result = RegistrationEnvironment::default();
    for inspection in inspections {
        for (key, value) in inspection {
            result.values.insert(key.clone(), value.clone());
            if !PROVIDER_SETTINGS.contains(&key.as_str()) {
                result.unknown_keys.insert(key.clone());
            }
        }
    }
    result
}

/// Combine independently owned setup and provider values.  Provider values
/// take precedence only on an exact key collision; unknown names remain
/// diagnostic metadata and never cross the registration boundary.
pub fn combine(
    setup: RegistrationEnvironment,
    provider: RegistrationEnvironment,
) -> RegistrationEnvironment {
    let mut values = setup.values;
    values.extend(provider.values);
    let mut unknown_keys = setup.unknown_keys;
    unknown_keys.extend(provider.unknown_keys);
    RegistrationEnvironment {
        values,
        unknown_keys,
    }
}

/// Reject explicitly selected provider settings that no provider inspection
/// admitted.  Setup and `mcp add` must fail closed here rather than silently
/// dropping a caller choice when readiness validation could not preserve it.
pub fn validate_provider_values(
    environment: &BTreeMap<String, String>,
    admitted: &BTreeMap<String, String>,
) -> Result<(), String> {
    for key in PROVIDER_SETTINGS {
        let Some(value) = environment.get(*key).filter(|value| !value.is_empty()) else {
            continue;
        };
        if admitted.get(*key) != Some(value) {
            return Err(format!(
                "provider setting `{key}` was not admitted by doctor validation; review its configuration and rerun setup"
            ));
        }
    }
    Ok(())
}

fn admit(environment: &BTreeMap<String, String>, allowed: &[&str]) -> RegistrationEnvironment {
    let mut result = RegistrationEnvironment::default();
    for (key, value) in environment {
        if allowed.contains(&key.as_str()) {
            result.values.insert(key.clone(), value.clone());
        } else {
            result.unknown_keys.insert(key.clone());
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_preserves_selected_values_without_defaults_or_ambient_values() {
        let input = BTreeMap::from([
            ("REA_ANALYSIS_PROVIDER".to_owned(), "ida".to_owned()),
            ("REA_GHIDRA_RUST_TIMEOUT_MS".to_owned(), "1000".to_owned()),
            ("PATH".to_owned(), "/private/secret/bin".to_owned()),
        ]);

        let result = explicit_setup_registration_environment(&input);

        assert_eq!(
            result.values,
            BTreeMap::from([
                ("REA_ANALYSIS_PROVIDER".to_owned(), "ida".to_owned()),
                ("REA_GHIDRA_RUST_TIMEOUT_MS".to_owned(), "1000".to_owned()),
            ])
        );
        assert_eq!(result.unknown_keys, BTreeSet::from(["PATH".to_owned()]));
    }

    #[test]
    fn provider_values_are_closed_and_unknown_values_are_not_retained() {
        let result = provider_registration_environment(&[BTreeMap::from([
            (
                "REA_JEB_MCP_URL".to_owned(),
                "http://127.0.0.1:8425/mcp".to_owned(),
            ),
            ("REA_FUTURE_SETTING".to_owned(), "future-value".to_owned()),
        ])]);

        assert_eq!(
            result.values.get("REA_JEB_MCP_URL"),
            Some(&"http://127.0.0.1:8425/mcp".to_owned())
        );
        assert_eq!(
            result.values.get("REA_FUTURE_SETTING"),
            Some(&"future-value".to_owned())
        );
        assert_eq!(
            result.unknown_keys,
            BTreeSet::from(["REA_FUTURE_SETTING".to_owned()])
        );
    }
}
