//! Argument parsing and endpoint defaults for the experimental native HTTP MCP entrypoint.

use std::net::IpAddr;

const DEFAULT_HOST: &str = "127.0.0.1";
const DEFAULT_PORT: u16 = 0;
const PORT_CONSTRAINT: &str = "MCP_PORT must be a decimal integer between 0 and 65535.";
const HOST_CONSTRAINT: &str = "MCP_HOST must be a non-empty host name or IP address.";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpCommand {
    Stdio,
    Help,
    Http { host: String, port: u16 },
}

/// Parse the command arguments after `mcp`, using the same environment fallbacks as TypeScript.
pub fn parse(arguments: &[String]) -> Result<McpCommand, String> {
    if arguments.is_empty() {
        return Ok(McpCommand::Stdio);
    }

    let mut http = false;
    let mut host_override = None;
    let mut port_override = None;
    let mut index = 0;

    while index < arguments.len() {
        let argument = arguments[index].as_str();

        if argument == "--help" || argument == "-h" {
            return Ok(McpCommand::Help);
        }

        if argument == "--http" {
            http = true;
            index += 1;
            continue;
        }

        let (flag, inline_value) = split_flag(argument);
        match flag {
            "--host" | "--port" => {
                let value = match inline_value {
                    Some(value) => value,
                    None => {
                        index += 1;
                        let Some(value) = arguments.get(index) else {
                            return Err(format!("Missing value for {flag}"));
                        };
                        if value.starts_with('-') {
                            return Err(format!("Missing value for {flag}"));
                        }
                        value
                    }
                };

                match flag {
                    "--host" => host_override = Some(value.to_owned()),
                    "--port" => port_override = Some(value.to_owned()),
                    _ => unreachable!("matched only the valued HTTP options"),
                }
            }
            _ => return Err(format!("Unknown mcp --http argument: {argument}")),
        }

        index += 1;
    }

    if !http {
        return Err("--host and --port require --http".into());
    }

    let host = resolve_host(host_override)?;
    let port = resolve_port(port_override)?;
    Ok(McpCommand::Http { host, port })
}

fn split_flag(argument: &str) -> (&str, Option<&str>) {
    match argument.split_once('=') {
        Some((flag, value)) => (flag, Some(value)),
        None => (argument, None),
    }
}

fn resolve_host(override_value: Option<String>) -> Result<String, String> {
    let (configured, explicit) = match override_value {
        Some(host) => (Some(host), true),
        None => (std::env::var("MCP_HOST").ok(), false),
    };

    let Some(configured) = configured else {
        return Ok(DEFAULT_HOST.into());
    };

    let host = configured.trim();
    if host.is_empty() {
        let message = if explicit {
            "--host must be a non-empty host name or IP address"
        } else {
            HOST_CONSTRAINT
        };
        return Err(message.into());
    }

    Ok(host.to_owned())
}

fn resolve_port(override_value: Option<String>) -> Result<u16, String> {
    let configured = match override_value {
        Some(port) => Some((port, false)),
        None => std::env::var("MCP_PORT").ok().map(|port| (port, true)),
    };

    let Some((configured, from_environment)) = configured else {
        return Ok(DEFAULT_PORT);
    };

    match parse_port(&configured) {
        Some(port) => Ok(port),
        None if from_environment => Err(PORT_CONSTRAINT.into()),
        None => Err(format!("Invalid --port: {PORT_CONSTRAINT}")),
    }
}

fn parse_port(value: &str) -> Option<u16> {
    let canonical_decimal = value == "0"
        || (!value.is_empty()
            && !value.starts_with('0')
            && value.bytes().all(|byte| byte.is_ascii_digit()));

    canonical_decimal.then(|| value.parse().ok()).flatten()
}

pub fn loopback_host_aliases(configured_host: &str, bound_host: IpAddr) -> Vec<String> {
    let mut hosts = vec!["localhost".into(), "127.0.0.1".into(), "::1".into()];
    hosts.push(configured_host.trim_matches(['[', ']']).to_owned());
    hosts.push(bound_host.to_string());
    hosts.sort_unstable();
    hosts.dedup();
    hosts
}

pub fn loopback_origin_aliases(configured_host: &str, bound_host: IpAddr) -> Vec<String> {
    loopback_host_aliases(configured_host, bound_host)
        .into_iter()
        .map(|host| {
            if host.contains(':') {
                format!("http://[{host}]:*")
            } else {
                format!("http://{host}:*")
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{McpCommand, parse, parse_port};

    fn arguments(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).into()).collect()
    }

    #[test]
    fn no_http_arguments_keeps_stdio_transport() {
        assert_eq!(parse(&[]), Ok(McpCommand::Stdio));
    }

    #[test]
    fn http_options_accept_inline_values_and_trim_host() {
        assert_eq!(
            parse(&arguments(&["--http", "--host= localhost ", "--port=4321"])),
            Ok(McpCommand::Http {
                host: "localhost".into(),
                port: 4321,
            })
        );
    }

    #[test]
    fn http_options_reject_noncanonical_or_out_of_range_ports() {
        for value in ["", "00", "01", "+1", "1.0", "65536", "999999"] {
            assert_eq!(parse_port(value), None, "unexpectedly accepted {value:?}");
        }
        assert_eq!(parse_port("0"), Some(0));
        assert_eq!(parse_port("65535"), Some(65535));
    }

    #[test]
    fn help_wins_even_when_http_flag_is_omitted() {
        assert_eq!(parse(&arguments(&["--help"])), Ok(McpCommand::Help));
    }

    #[test]
    fn host_and_port_require_http_mode() {
        assert_eq!(
            parse(&arguments(&["--host", "localhost"])),
            Err("--host and --port require --http".into())
        );
    }
}
