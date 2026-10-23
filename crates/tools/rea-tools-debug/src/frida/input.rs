//! Cross-field input refinements and the Frida remote-address predicate.
//!
//! The frozen catalog carries only the base JSON Schema (type, required,
//! lengths, enums, uuid). The original contracts in
//! `src/contracts/fridaToolContracts.ts` add Zod `.refine` cross-field checks
//! and the `isValidFridaRemoteAddress` predicate, which fail at the SDK
//! boundary as text-only `Input validation error: ...` results. This module
//! ports those refinements exactly and renders the identical failure text via
//! `rea_mcp::schema`.
#![allow(dead_code)]

use rea_mcp::schema::{Issue, validation_error_text};
use serde_json::Value;

/// `isValidFridaRemoteAddress`: a host, optionally with a TCP port, without
/// URL credentials, path, query or fragment.
pub(crate) fn is_valid_frida_remote_address(address: &str) -> bool {
    if address.is_empty() || address.len() > 2048 {
        return false;
    }
    // `/[?@#\s\u0000-\u001f\u007f/]/u`
    if address.chars().any(|c| {
        matches!(c, '?' | '@' | '#' | '/' | '\u{7f}')
            || c.is_whitespace()
            || (c as u32) <= 0x1f
    }) {
        return false;
    }
    if address.ends_with(':') {
        return false;
    }
    // Equivalent of `new URL("tcp://" + address)` after the character guards
    // above already excluded userinfo (`@`), path (`/`), query (`?`) and
    // fragment (`#`). What remains is `host` or `host:port`, including
    // bracketed IPv6 literals.
    let (host, port) = split_host_port(address);
    if host.is_empty() {
        return false;
    }
    match port {
        None => true,
        Some(port_text) => match port_text.parse::<u32>() {
            Ok(port) => port > 0 && port <= 65_535,
            Err(_) => false,
        },
    }
}

/// Split `host` / `host:port`, honoring bracketed IPv6 literals. A trailing
/// colon was already rejected by the caller.
fn split_host_port(address: &str) -> (&str, Option<&str>) {
    if let Some(rest) = address.strip_prefix('[') {
        // `[ipv6]` or `[ipv6]:port`.
        if let Some(close) = rest.find(']') {
            let host = &rest[..close];
            let after = &rest[close + 1..];
            if let Some(port) = after.strip_prefix(':') {
                return (host, Some(port));
            }
            return (host, None);
        }
        return (address, None);
    }
    match address.rfind(':') {
        // Only treat the last colon as a port separator when the host part has
        // no other colon (an unbracketed IPv6 literal is not a valid URL host).
        Some(index) if !address[..index].contains(':') => {
            (&address[..index], Some(&address[index + 1..]))
        }
        _ => (address, None),
    }
}

/// `str_or_undefined`: the string at `key`, or `None` when absent/null.
fn field<'a>(input: &'a Value, key: &str) -> Option<&'a Value> {
    match input.get(key) {
        None | Some(Value::Null) => None,
        other => other,
    }
}

fn present(input: &Value, key: &str) -> bool {
    field(input, key).is_some()
}

fn remote_address(input: &Value) -> Option<&Value> {
    field(input, "remote").and_then(|remote| remote.get("address"))
}

/// A refinement failure rendered exactly as the SDK boundary text.
pub(crate) fn refinement_text(tool: &str, path: &[&str], message: &str) -> String {
    let issue = Issue {
        path: path.iter().map(|part| (*part).to_owned()).collect(),
        message: message.to_owned(),
    };
    validation_error_text(tool, &[issue])
}

/// `start_frida_session` refinements: the remote-address predicate, then the
/// device/mode cross-field rule. Returns the first failing text, or `None`.
pub(crate) fn start_refinement(input: &Value) -> Option<String> {
    const TOOL: &str = "start_frida_session";
    if let Some(text) = remote_address_refinement(TOOL, input) {
        return Some(text);
    }
    let mode = field(input, "mode").and_then(Value::as_str);
    let attach_ok = mode == Some("attach")
        && present(input, "pid")
        && !present(input, "program")
        && !present(input, "argv");
    let spawn_ok =
        mode == Some("spawn") && present(input, "program") && !present(input, "pid");
    let device_ok = !(present(input, "device_id") && present(input, "remote"));
    if (attach_ok || spawn_ok) && device_ok {
        None
    } else {
        Some(refinement_text(
            TOOL,
            &[],
            "Select one device; attach requires pid; spawn requires program and rejects pid",
        ))
    }
}

/// `list_frida_processes` refinements: exclusive device selector, then the
/// "select one" rule, then the remote-address predicate — in Zod order.
pub(crate) fn list_processes_refinement(input: &Value) -> Option<String> {
    const TOOL: &str = "list_frida_processes";
    if present(input, "device_id") && present(input, "remote") {
        return Some(refinement_text(
            TOOL,
            &[],
            "Choose either device_id or remote, not both",
        ));
    }
    if !present(input, "device_id") && !present(input, "remote") {
        return Some(refinement_text(
            TOOL,
            &[],
            "Select a device_id or a remote endpoint",
        ));
    }
    remote_address_refinement(TOOL, input)
}

/// `list_frida_devices` / shared remote-address refinement.
pub(crate) fn remote_address_refinement(tool: &str, input: &Value) -> Option<String> {
    let address = remote_address(input)?;
    let valid = address
        .as_str()
        .is_some_and(is_valid_frida_remote_address);
    if valid {
        None
    } else {
        Some(refinement_text(
            tool,
            &["remote", "address"],
            "Expected a Frida host address, optionally followed by a port",
        ))
    }
}

/// `load_frida_script` source refinement.
pub(crate) fn load_refinement(input: &Value) -> Option<String> {
    const TOOL: &str = "load_frida_script";
    if source_fields_ok(input) {
        None
    } else {
        Some(refinement_text(
            TOOL,
            &[],
            "Inline source requires source; file source requires path",
        ))
    }
}

/// `instrument_with_frida` combined device/mode/source refinement.
pub(crate) fn instrument_refinement(input: &Value) -> Option<String> {
    const TOOL: &str = "instrument_with_frida";
    let mode = field(input, "mode").and_then(Value::as_str);
    let device_ok = !(present(input, "device_id") && present(input, "remote"));
    let attach_ok = mode == Some("attach")
        && present(input, "pid")
        && !present(input, "program")
        && !present(input, "argv");
    let spawn_ok =
        mode == Some("spawn") && present(input, "program") && !present(input, "pid");
    if device_ok && (attach_ok || spawn_ok) && source_fields_ok(input) {
        None
    } else {
        Some(refinement_text(
            TOOL,
            &[],
            "Select one device and provide fields matching the mode and source_kind",
        ))
    }
}

fn source_fields_ok(input: &Value) -> bool {
    let kind = field(input, "source_kind").and_then(Value::as_str);
    let inline_ok =
        kind == Some("inline") && present(input, "source") && !present(input, "path");
    let file_ok = kind == Some("file") && present(input, "path") && !present(input, "source");
    inline_ok || file_ok
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn accepts_host_and_host_port() {
        assert!(is_valid_frida_remote_address("127.0.0.1"));
        assert!(is_valid_frida_remote_address("127.0.0.1:27042"));
        assert!(is_valid_frida_remote_address("example.com"));
        assert!(is_valid_frida_remote_address("[::1]:27042"));
    }

    #[test]
    fn rejects_credentials_paths_and_trailing_colon() {
        assert!(!is_valid_frida_remote_address("user@host:27042"));
        assert!(!is_valid_frida_remote_address("host:"));
        assert!(!is_valid_frida_remote_address("host/path"));
        assert!(!is_valid_frida_remote_address("host:70000"));
        assert!(!is_valid_frida_remote_address(""));
    }

    #[test]
    fn start_refinement_messages_match_oracle() {
        // Missing pid/program.
        assert_eq!(
            start_refinement(&json!({"mode": "attach", "device_id": "local"})),
            Some(
                "Input validation error: Invalid arguments for tool start_frida_session: \
                 Select one device; attach requires pid; spawn requires program and rejects pid"
                    .to_owned()
            )
        );
        // Valid attach passes.
        assert_eq!(
            start_refinement(&json!({"mode": "attach", "device_id": "local", "pid": 5})),
            None
        );
        // Bad remote address wins first.
        assert_eq!(
            start_refinement(&json!({"mode": "attach", "remote": {"address": "host:"}, "pid": 5})),
            Some(
                "Input validation error: Invalid arguments for tool start_frida_session: \
                 remote.address: Expected a Frida host address, optionally followed by a port"
                    .to_owned()
            )
        );
    }

    #[test]
    fn list_processes_refinement_messages_match_oracle() {
        assert_eq!(
            list_processes_refinement(&json!({})),
            Some(
                "Input validation error: Invalid arguments for tool list_frida_processes: \
                 Select a device_id or a remote endpoint"
                    .to_owned()
            )
        );
        assert_eq!(
            list_processes_refinement(
                &json!({"device_id": "local", "remote": {"address": "127.0.0.1"}})
            ),
            Some(
                "Input validation error: Invalid arguments for tool list_frida_processes: \
                 Choose either device_id or remote, not both"
                    .to_owned()
            )
        );
        assert_eq!(
            list_processes_refinement(&json!({"device_id": "local"})),
            None
        );
    }

    #[test]
    fn load_and_instrument_refinements() {
        assert!(load_refinement(&json!({"session_id": "x", "source_kind": "inline"})).is_some());
        assert_eq!(
            load_refinement(&json!({"session_id": "x", "source_kind": "inline", "source": "1"})),
            None
        );
        assert_eq!(
            instrument_refinement(&json!({"mode": "attach", "pid": 5, "source_kind": "file"})),
            Some(
                "Input validation error: Invalid arguments for tool instrument_with_frida: \
                 Select one device and provide fields matching the mode and source_kind"
                    .to_owned()
            )
        );
    }
}
