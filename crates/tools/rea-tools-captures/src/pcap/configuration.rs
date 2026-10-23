//! Resolve and version-check the caller's tshark and capinfos binaries.
//!
//! Compatibility owner: `src/pcap/PcapConfiguration.ts`. Each tool accepts an
//! absolute environment path or falls back to PATH resolution. REA never
//! installs the Wireshark suite.
use crate::errors;
use crate::node;
use rea_core::analysis_error::AnalysisError;
use std::collections::HashMap;

pub const TSHARK_COMMAND_ENV: &str = "REA_TSHARK_COMMAND";
pub const CAPINFOS_COMMAND_ENV: &str = "REA_CAPINFOS_COMMAND";

fn tool_remediation() -> String {
    format!(
        "Supply Wireshark 4.x tshark and capinfos on PATH or through absolute {TSHARK_COMMAND_ENV} and {CAPINFOS_COMMAND_ENV}; REA does not install them."
    )
}

/// `pcapToolUnavailable`: host-tool refusal carrying its own remediation.
pub fn tool_unavailable(operation: &str, reason: &str) -> AnalysisError {
    let ends_with_punctuation = reason
        .chars()
        .last()
        .is_some_and(|character| matches!(character, '.' | '!' | '?'));
    let user_message = if ends_with_punctuation {
        format!("{reason} {}", tool_remediation())
    } else {
        format!("{reason}. {}", tool_remediation())
    };
    errors::capability("pcap", operation, reason, Some(user_message))
}

/// How each tool was selected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Environment,
    Path,
}
impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Environment => "environment",
            Self::Path => "path",
        }
    }
}

/// Selected command and the source that produced it.
#[derive(Clone, Debug)]
pub struct ToolChoice {
    pub command: String,
    pub source: Source,
}

/// Resolved tshark and capinfos selection.
#[derive(Clone, Debug)]
pub struct ToolSelection {
    pub tshark: ToolChoice,
    pub capinfos: ToolChoice,
}

/// A configuration refusal about the caller's Wireshark installation.
///
/// `code` and `diagnostics` mirror the original availability surface. This
/// crate reports only `message` through `tool_unavailable`; the richer
/// availability projection is owned by the orchestrator (server admission is
/// skipped here), so those members are retained for contract parity but not
/// yet consumed.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct ConfigurationFailure {
    pub code: FailureCode,
    pub message: String,
    pub diagnostics: Vec<(String, serde_json::Value)>,
}

/// Configuration failure codes mirroring `PcapConfigurationFailureCode`.
///
/// The `*_missing` codes and the `rejection_code`/`as_str` projections feed
/// the availability view the orchestrator owns; they are preserved for exact
/// contract parity though unused in this crate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub enum FailureCode {
    TsharkNotAbsolute,
    CapinfosNotAbsolute,
    TsharkMissing,
    CapinfosMissing,
    TsharkVersionUnresolved,
    CapinfosVersionUnresolved,
    TsharkVersionUnsupported,
    CapinfosVersionUnsupported,
}
#[allow(dead_code)]
impl FailureCode {
    fn rejection_code(self) -> &'static str {
        let text = self.as_str();
        if text.contains("missing") {
            "executable_missing"
        } else if text.contains("unsupported") {
            "unsupported_version"
        } else if text.contains("not_absolute") {
            "not_configured"
        } else {
            "version_unresolved"
        }
    }
    fn as_str(self) -> &'static str {
        match self {
            Self::TsharkNotAbsolute => "tshark_not_absolute",
            Self::CapinfosNotAbsolute => "capinfos_not_absolute",
            Self::TsharkMissing => "tshark_missing",
            Self::CapinfosMissing => "capinfos_missing",
            Self::TsharkVersionUnresolved => "tshark_version_unresolved",
            Self::CapinfosVersionUnresolved => "capinfos_version_unresolved",
            Self::TsharkVersionUnsupported => "tshark_version_unsupported",
            Self::CapinfosVersionUnsupported => "capinfos_version_unsupported",
        }
    }
}

fn blank(value: Option<&String>) -> bool {
    value.is_none_or(|text| text.trim().is_empty())
}

/// `resolvePcapTools`.
pub fn resolve_tools(
    environment: &HashMap<String, String>,
) -> Result<ToolSelection, ConfigurationFailure> {
    let tshark_env = environment.get(TSHARK_COMMAND_ENV);
    let capinfos_env = environment.get(CAPINFOS_COMMAND_ENV);

    if let Some(value) = tshark_env
        && !value.trim().is_empty()
        && !node::is_absolute(value)
    {
        return Err(ConfigurationFailure {
            code: FailureCode::TsharkNotAbsolute,
            message: format!("{TSHARK_COMMAND_ENV} must be an absolute path to the tshark binary"),
            diagnostics: vec![("configured".into(), serde_json::json!(value))],
        });
    }
    if let Some(value) = capinfos_env
        && !value.trim().is_empty()
        && !node::is_absolute(value)
    {
        return Err(ConfigurationFailure {
            code: FailureCode::CapinfosNotAbsolute,
            message: format!(
                "{CAPINFOS_COMMAND_ENV} must be an absolute path to the capinfos binary"
            ),
            diagnostics: vec![("configured".into(), serde_json::json!(value))],
        });
    }

    let tshark = if blank(tshark_env) {
        ToolChoice {
            command: "tshark".into(),
            source: Source::Path,
        }
    } else {
        ToolChoice {
            command: tshark_env.expect("non-blank").clone(),
            source: Source::Environment,
        }
    };
    let capinfos = if blank(capinfos_env) {
        ToolChoice {
            command: "capinfos".into(),
            source: Source::Path,
        }
    } else {
        ToolChoice {
            command: capinfos_env.expect("non-blank").clone(),
            source: Source::Environment,
        }
    };
    Ok(ToolSelection { tshark, capinfos })
}

/// Which tool a version banner is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tool {
    Tshark,
    Capinfos,
}
impl Tool {
    fn name(self) -> &'static str {
        match self {
            Self::Tshark => "tshark",
            Self::Capinfos => "capinfos",
        }
    }
    fn unsupported_code(self) -> FailureCode {
        match self {
            Self::Tshark => FailureCode::TsharkVersionUnsupported,
            Self::Capinfos => FailureCode::CapinfosVersionUnsupported,
        }
    }
}

/// `parseVersion`: recognize `tool (Wireshark) <major>.<minor>.<patch>`.
pub fn parse_version(stdout: &str, tool: Tool) -> Result<Option<String>, ConfigurationFailure> {
    let line = stdout
        .split('\n')
        .map(|entry| entry.strip_suffix('\r').unwrap_or(entry).trim())
        .find(|entry| !entry.is_empty());
    let Some(line) = line else {
        return Ok(None);
    };
    // `^{tool} \(Wireshark\) (\d+)\.\d+\.\d+` case-insensitive.
    let pattern = format!(
        r"^{} \(Wireshark\) (\d+)\.\d+\.\d+",
        regex::escape(tool.name())
    );
    let regex = regex::RegexBuilder::new(&pattern)
        .case_insensitive(true)
        .build()
        .expect("static version pattern");
    let Some(captures) = regex.captures(line) else {
        return Ok(None);
    };
    let major = captures
        .get(1)
        .map(|value| value.as_str())
        .unwrap_or_default();
    if major != "4" {
        return Err(ConfigurationFailure {
            code: tool.unsupported_code(),
            message: "Packet summary inspection currently requires Wireshark 4.x tools; select an installation with the admitted output profile.".into(),
            diagnostics: vec![("version".into(), serde_json::json!(line))],
        });
    }
    Ok(Some(line.to_owned()))
}

/// Projected pcap client identity.
#[derive(Clone, Debug)]
pub struct ClientIdentity {
    pub tshark_version: Option<String>,
    pub capinfos_version: Option<String>,
}
