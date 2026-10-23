//! Host allowlist primitives for loopback streamable HTTP MCP listeners.
//!
//! A configured DNS name is admitted only as an alias for a listener that is
//! already proven to be loopback. Binding to a non-loopback address disables
//! the local allowlist, matching the TypeScript transport's authority rule.

use std::net::{IpAddr, Ipv6Addr};

const LOOPBACK_HOSTS: [&str; 3] = ["localhost", "127.0.0.1", "[::1]"];

/// Return the MCP Host allowlist for a loopback bind, or `None` for a public bind.
pub fn host_header_allowlist(configured_host: &str, bound_address: &str) -> Option<Vec<String>> {
    let bound = normalize_hostname(bound_address)?;
    if !is_loopback_hostname(&bound) {
        return None;
    }

    let mut allowlist = LOOPBACK_HOSTS.map(str::to_owned).to_vec();
    if let Some(configured) = normalize_hostname(configured_host) {
        append_unique(&mut allowlist, configured);
    }
    append_unique(&mut allowlist, bound);
    Some(allowlist)
}

fn append_unique(values: &mut Vec<String>, candidate: String) {
    if !values.iter().any(|value| value == &candidate) {
        values.push(candidate);
    }
}

fn normalize_hostname(value: &str) -> Option<String> {
    if let Ok(address) = value.parse::<IpAddr>() {
        return Some(match address {
            IpAddr::V4(address) => address.to_string(),
            IpAddr::V6(address) => canonical_ipv6_host(address),
        });
    }

    if value.is_empty()
        || value.chars().any(|character| {
            character.is_ascii_whitespace() || matches!(character, '/' | '\\' | ':' | '[' | ']')
        })
    {
        return None;
    }

    Some(value.to_ascii_lowercase())
}

fn canonical_ipv6_host(address: Ipv6Addr) -> String {
    let segments = address.segments();
    if address.to_ipv4().is_some() {
        return format!("[::ffff:{:x}:{:x}]", segments[6], segments[7]);
    }

    format!("[{address}]")
}

fn is_loopback_hostname(hostname: &str) -> bool {
    let address = hostname.trim_matches(['[', ']']);
    let Ok(address) = address.parse::<IpAddr>() else {
        return false;
    };

    match address {
        IpAddr::V4(address) => address.is_loopback(),
        IpAddr::V6(address) => address == Ipv6Addr::LOCALHOST || mapped_loopback(address),
    }
}

fn mapped_loopback(address: Ipv6Addr) -> bool {
    address.to_ipv4().is_some_and(|mapped| mapped.is_loopback())
}

#[cfg(test)]
mod tests {
    use super::host_header_allowlist;

    #[test]
    fn preserves_sdk_loopback_hosts_and_adds_configured_alias() {
        assert_eq!(
            host_header_allowlist("dev.local", "127.0.0.1"),
            Some(vec![
                "localhost".into(),
                "127.0.0.1".into(),
                "[::1]".into(),
                "dev.local".into(),
            ])
        );
    }

    #[test]
    fn rejects_non_loopback_bindings_and_invalid_configured_names() {
        assert_eq!(host_header_allowlist("example.com", "192.0.2.10"), None);
        assert_eq!(
            host_header_allowlist("not a host", "127.0.0.1"),
            Some(vec!["localhost".into(), "127.0.0.1".into(), "[::1]".into(),])
        );
    }

    #[test]
    fn recognizes_ipv4_mapped_loopback_and_canonicalizes_ipv6() {
        assert_eq!(
            host_header_allowlist("::ffff:127.0.0.1", "::ffff:127.0.0.1"),
            Some(vec![
                "localhost".into(),
                "127.0.0.1".into(),
                "[::1]".into(),
                "[::ffff:7f00:1]".into(),
            ])
        );
    }
}
