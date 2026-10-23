//! Offline packet-capture projection.
//!
//! This module deliberately has no process, socket, or provider authority. A
//! caller supplies either the capture bytes or records already decoded by a
//! caller-owned decoder. Raw bytes are used only for identity and container
//! framing; protocol facts are retained only when decoded records are supplied.

use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const OPERATION: &str = "inspect_pcap_capture";
pub const MAX_INPUT_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_RECORDS: usize = 1_000_000;
pub const MAX_RETAINED_BYTES: usize = 16 * 1024 * 1024;

/// Metadata supplied by capinfos or another caller-owned decoder.
#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
pub struct CaptureMetadata {
    pub file_type: Option<String>,
    pub encapsulation: Option<String>,
    pub packet_count: Option<u64>,
    pub capture_start: Option<String>,
    pub capture_end: Option<String>,
    pub capture_duration_seconds: Option<f64>,
    pub snapshot_length: Option<u64>,
}

/// A decoded tshark-like packet. `layers` contains arrays of strings, as in
/// the producer protocol; an optional source pointer preserves provenance.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct DecodedRecord {
    pub layers: Map<String, Value>,
    #[serde(default)]
    pub source: Option<Value>,
}

#[derive(Clone, Debug)]
struct Facts {
    endpoints: BTreeMap<String, u64>,
    dns: BTreeMap<String, BTreeSet<String>>,
    sni: BTreeSet<String>,
    protocols: BTreeMap<String, u64>,
    uris: BTreeSet<String>,
    observed_uris: BTreeSet<String>,
    uri_redactions: u64,
    unattributed: BTreeSet<String>,
    unattributed_packets: u64,
    records: usize,
}

impl Facts {
    fn new() -> Self {
        Self {
            endpoints: BTreeMap::new(),
            dns: BTreeMap::new(),
            sni: BTreeSet::new(),
            protocols: BTreeMap::new(),
            uris: BTreeSet::new(),
            observed_uris: BTreeSet::new(),
            uri_redactions: 0,
            unattributed: BTreeSet::new(),
            unattributed_packets: 0,
            records: 0,
        }
    }
}

/// Inspect bytes without invoking a decoder. Container framing is recognized
/// for classic PCAP and PCAPNG; protocol inventories remain explicitly empty.
pub fn inspect_bytes(
    path: &str,
    bytes: &[u8],
    metadata: CaptureMetadata,
) -> Result<Value, Failure> {
    validate_path(path)?;
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(resource("capture exceeds the 32 MiB input limit"));
    }
    let framing = parse_framing(bytes)?;
    let digest = sha256(bytes);
    let mut metadata = metadata;
    if metadata.packet_count.is_none() {
        metadata.packet_count = framing.packet_count;
    }
    if metadata.snapshot_length.is_none() {
        metadata.snapshot_length = framing.snapshot_length;
    }
    result(
        path,
        bytes.len(),
        digest,
        metadata,
        Facts::new(),
        "partial",
        framing.format,
    )
}

/// Inspect records decoded by a caller. No bytes are inferred from record
/// contents, and every retained fact is derived from the supplied records.
pub fn inspect_records(
    path: &str,
    capture_bytes: Option<&[u8]>,
    records: &[DecodedRecord],
    metadata: CaptureMetadata,
) -> Result<Value, Failure> {
    validate_path(path)?;
    if records.len() > MAX_RECORDS {
        return Err(resource(
            "decoded packet records exceed the one-million record limit",
        ));
    }
    let (bytes, digest) = match capture_bytes {
        Some(bytes) if bytes.len() <= MAX_INPUT_BYTES => (bytes.len(), sha256(bytes)),
        Some(_) => return Err(resource("capture exceeds the 32 MiB input limit")),
        None => (0, String::new()),
    };
    let facts = aggregate(records)?;
    let packet_count = metadata.packet_count.or(Some(records.len() as u64));
    let metadata = CaptureMetadata {
        packet_count,
        ..metadata
    };
    let format = metadata.file_type.clone();
    result(path, bytes, digest, metadata, facts, "complete", format)
}

/// Parse the JSON form accepted at the application boundary. The object must
/// contain either `bytes_base64` or `records`; a path is retained as source
/// identity and is never opened by this module.
pub fn inspect(input: &Value) -> Result<Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("input must be an object"))?;
    let path = object
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("path must be a string"))?;
    let metadata = object.get("metadata").cloned().unwrap_or_else(|| json!({}));
    let metadata: CaptureMetadata =
        serde_json::from_value(metadata).map_err(|_| invalid("metadata is malformed"))?;
    if let Some(records) = object.get("records") {
        let records = decode_records(records)?;
        return inspect_records(path, None, &records, metadata);
    }
    let encoded = object
        .get("bytes_base64")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("supply bytes_base64 or records"))?;
    let bytes = base64_decode(encoded)?;
    inspect_bytes(path, &bytes, metadata)
}

fn decode_records(value: &Value) -> Result<Vec<DecodedRecord>, Failure> {
    let values = value
        .as_array()
        .ok_or_else(|| invalid("records must be an array"))?;
    if values.len() > MAX_RECORDS {
        return Err(resource(
            "decoded packet records exceed the one-million record limit",
        ));
    }
    values
        .iter()
        .map(|value| {
            let object = value
                .as_object()
                .ok_or_else(|| invalid("each decoded record must be an object"))?;
            let layers = object
                .get("layers")
                .or_else(|| {
                    object
                        .get("_source")
                        .and_then(Value::as_object)
                        .and_then(|source| source.get("layers"))
                })
                .and_then(Value::as_object)
                .cloned()
                .ok_or_else(|| invalid("each decoded record must contain layers"))?;
            Ok(DecodedRecord {
                layers,
                source: object.get("source").cloned(),
            })
        })
        .collect()
}

fn aggregate(records: &[DecodedRecord]) -> Result<Facts, Failure> {
    let mut facts = Facts::new();
    let mut retained = 0usize;
    for (index, record) in records.iter().enumerate() {
        let frame = strings(record, "frame.number")?;
        if frame.len() != 1 || frame[0] != (index + 1).to_string() {
            return Err(protocol(
                "frame inventory is missing, duplicated or out of order",
            ));
        }
        let protocols = strings(record, "frame.protocols")?;
        if protocols.len() != 1 || protocols[0].is_empty() {
            return Err(protocol(
                "packet protocol inventory is missing or ambiguous",
            ));
        }
        charge(&mut retained, &protocols[0])?;
        *facts.protocols.entry(protocols[0].clone()).or_default() += 1;
        for address in unique_strings(record, &["ip.src", "ip.dst", "ipv6.src", "ipv6.dst"])? {
            charge(&mut retained, &address)?;
            *facts.endpoints.entry(address).or_default() += 1;
        }
        let questions = unique_strings(record, &["dns.qry.name"])?;
        for question in &questions {
            charge(&mut retained, question)?;
            facts.dns.entry(question.clone()).or_default();
        }
        let addresses = unique_strings(record, &["dns.a", "dns.aaaa"])?;
        if !addresses.is_empty() {
            let response = strings(record, "dns.flags.response")?;
            if questions.len() == 1
                && !response.is_empty()
                && response.iter().all(|v| v == "True" || v == "1")
            {
                for address in addresses {
                    charge(&mut retained, &address)?;
                    facts.dns.get_mut(&questions[0]).unwrap().insert(address);
                }
            } else {
                facts.unattributed_packets += 1;
                for address in addresses {
                    charge(&mut retained, &address)?;
                    facts.unattributed.insert(address);
                }
            }
        }
        for value in unique_strings(record, &["tls.handshake.extensions_server_name"])? {
            charge(&mut retained, &value)?;
            facts.sni.insert(value);
        }
        for value in strings(record, "http.request.full_uri")? {
            if value.is_empty() || !facts.observed_uris.insert(value.clone()) {
                continue;
            }
            charge(&mut retained, &value)?;
            if let Some((clean, redacted)) = redact_uri(&value) {
                if redacted {
                    facts.uri_redactions += 1;
                }
                if let Some(clean) = clean {
                    facts.uris.insert(clean);
                }
            }
        }
        facts.records += 1;
    }
    Ok(facts)
}

fn result(
    path: &str,
    bytes: usize,
    digest: String,
    metadata: CaptureMetadata,
    facts: Facts,
    coverage: &str,
    inferred_format: Option<String>,
) -> Result<Value, Failure> {
    let endpoints = facts
        .endpoints
        .iter()
        .map(|(address, count)| json!({"address":address,"port":Value::Null,"packet_count":count}))
        .collect::<Vec<_>>();
    let dns_queries = facts.dns.iter().map(|(query, addresses)| json!({"query":query,"response_addresses":addresses,"response_address_count":addresses.len()})).collect::<Vec<_>>();
    let protocols = facts
        .protocols
        .iter()
        .map(|(protocol, count)| json!({"protocol":protocol,"packet_count":count}))
        .collect::<Vec<_>>();
    let packet_count = metadata
        .packet_count
        .or((facts.records > 0).then_some(facts.records as u64));
    let output = json!({
        "client": null,
        "target":{"path":path,"bytes":bytes,"sha256":digest},
        "file_type":metadata.file_type.or(inferred_format), "encapsulation":metadata.encapsulation,
        "packet_count":packet_count, "capture_start":metadata.capture_start, "capture_end":metadata.capture_end,
        "capture_duration_seconds":metadata.capture_duration_seconds, "snapshot_length":metadata.snapshot_length,
        "endpoints":endpoints,"endpoint_count":facts.endpoints.len(),"dns_queries":dns_queries,"dns_query_count":facts.dns.len(),
        "tls_sni_values":facts.sni,"tls_sni_count":facts.sni.len(),"protocol_distribution":protocols,"protocol_count":facts.protocols.len(),
        "http_request_uris":facts.uris,"http_request_uri_count":facts.observed_uris.len(),"http_uri_redaction_count":facts.uri_redactions,
        "unattributed_dns_addresses":facts.unattributed,"unattributed_dns_address_count":facts.unattributed.len(),"unattributed_dns_packet_count":facts.unattributed_packets,
        "coverage":coverage,"limitations":["Native inspection is offline and never captures traffic or contacts a target.","Protocol facts are retained only from caller-supplied decoded records; raw bytes alone do not establish protocol absence."]
    });
    if serde_json::to_vec(&output)
        .map_err(|_| resource("unable to serialize capture result"))?
        .len()
        > MAX_RETAINED_BYTES
    {
        return Err(resource("capture result exceeds the retained-fact budget"));
    }
    Ok(output)
}

fn strings(record: &DecodedRecord, key: &str) -> Result<Vec<String>, Failure> {
    record
        .layers
        .get(key)
        .map(|value| {
            value
                .as_array()
                .ok_or_else(|| protocol("decoded layer must be an array of strings"))
                .and_then(|values| {
                    values
                        .iter()
                        .map(|value| {
                            value
                                .as_str()
                                .map(str::to_owned)
                                .ok_or_else(|| protocol("decoded layer must contain strings"))
                        })
                        .collect()
                })
        })
        .transpose()
        .map(|v| v.unwrap_or_default())
}

fn unique_strings(record: &DecodedRecord, keys: &[&str]) -> Result<Vec<String>, Failure> {
    let mut values = BTreeSet::new();
    for key in keys {
        for value in strings(record, key)? {
            if !value.is_empty() {
                values.insert(value);
            }
        }
    }
    Ok(values.into_iter().collect())
}

fn redact_uri(value: &str) -> Option<(Option<String>, bool)> {
    let Some(scheme) = value.find("://") else {
        return Some((Some(value.to_owned()), false));
    };
    let authority_start = scheme + 3;
    let authority_end = value[authority_start..]
        .find(['/', '?', '#'])
        .map_or(value.len(), |offset| authority_start + offset);
    let authority = &value[authority_start..authority_end];
    let Some(at) = authority.rfind('@') else {
        return Some((Some(value.to_owned()), false));
    };
    let clean = format!(
        "{}{}{}",
        &value[..authority_start],
        &authority[at + 1..],
        &value[authority_end..]
    );
    Some((Some(clean), true))
}

struct Framing {
    format: Option<String>,
    packet_count: Option<u64>,
    snapshot_length: Option<u64>,
}
fn parse_framing(bytes: &[u8]) -> Result<Framing, Failure> {
    if bytes.len() < 4 {
        return Err(invalid("capture is too short to identify a pcap container"));
    }
    let magic = &bytes[..4];
    if matches!(
        magic,
        [0xd4, 0xc3, 0xb2, 0xa1]
            | [0xa1, 0xb2, 0xc3, 0xd4]
            | [0x4d, 0x3c, 0xb2, 0xa1]
            | [0xa1, 0xb2, 0x3c, 0x4d]
    ) {
        if bytes.len() < 24 {
            return Err(invalid("classic pcap header is truncated"));
        }
        let little = matches!(magic, [0xd4, 0xc3, 0xb2, 0xa1] | [0x4d, 0x3c, 0xb2, 0xa1]);
        let read = |offset| {
            if little {
                u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
            } else {
                u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap())
            }
        };
        let mut offset = 24usize;
        let mut count = 0u64;
        let snap = read(16) as u64;
        while offset < bytes.len() {
            if bytes.len() - offset < 16 {
                return Err(invalid("classic pcap packet header is truncated"));
            }
            let length = read(offset + 8) as usize;
            offset = offset
                .checked_add(16 + length)
                .ok_or_else(|| resource("pcap packet length overflow"))?;
            if offset > bytes.len() {
                return Err(invalid("classic pcap packet bytes are truncated"));
            }
            count += 1;
            if count > MAX_RECORDS as u64 {
                return Err(resource(
                    "packet count exceeds the one-million record limit",
                ));
            }
        }
        return Ok(Framing {
            format: Some("pcap".into()),
            packet_count: Some(count),
            snapshot_length: (snap > 0).then_some(snap),
        });
    }
    if matches!(magic, [0x0a, 0x0d, 0x0d, 0x0a]) {
        if bytes.len() < 28 {
            return Err(invalid("pcapng section header is truncated"));
        }
        let byte_order = &bytes[8..12];
        let little = match byte_order {
            [0x4d, 0x3c, 0x2b, 0x1a] => true,
            [0x1a, 0x2b, 0x3c, 0x4d] => false,
            _ => return Err(invalid("pcapng byte-order marker is invalid")),
        };
        let read_u32 = |value: &[u8]| {
            if little {
                u32::from_le_bytes(value.try_into().unwrap())
            } else {
                u32::from_be_bytes(value.try_into().unwrap())
            }
        };
        let mut offset = 0usize;
        let mut count = 0u64;
        while offset < bytes.len() {
            if bytes.len() - offset < 12 {
                return Err(invalid("pcapng block header is truncated"));
            }
            let length = read_u32(&bytes[offset + 4..offset + 8]) as usize;
            if length < 12 || length % 4 != 0 || length > bytes.len() - offset {
                return Err(invalid("pcapng block length is invalid or truncated"));
            }
            let block_type = read_u32(&bytes[offset..offset + 4]);
            if block_type == 0x00000006 || block_type == 0x00000003 {
                count += 1;
                if count > MAX_RECORDS as u64 {
                    return Err(resource(
                        "packet count exceeds the one-million record limit",
                    ));
                }
            }
            let trailer = offset + length - 4;
            let trailer_length = read_u32(&bytes[trailer..trailer + 4]) as usize;
            if trailer_length != length {
                return Err(invalid(
                    "pcapng block trailer length does not match its header",
                ));
            }
            offset += length;
        }
        return Ok(Framing {
            format: Some("pcapng".into()),
            packet_count: Some(count),
            snapshot_length: None,
        });
    }
    Err(invalid(
        "capture is not a recognized classic pcap or pcapng container",
    ))
}

fn base64_decode(encoded: &str) -> Result<Vec<u8>, Failure> {
    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded)
        .map_err(|_| invalid("bytes_base64 is malformed"))
}
fn sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
fn charge(retained: &mut usize, value: &str) -> Result<(), Failure> {
    *retained = retained.saturating_add(192 + value.len().saturating_mul(2));
    if *retained > MAX_RETAINED_BYTES {
        Err(resource(
            "decoded packet inventory exceeds the retained-fact budget",
        ))
    } else {
        Ok(())
    }
}
fn validate_path(path: &str) -> Result<(), Failure> {
    if path.is_empty() {
        Err(invalid("path must be non-empty"))
    } else {
        Ok(())
    }
}
fn invalid(message: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        message.into(),
        true,
        "Correct the input and retry.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
fn protocol(message: &str) -> Failure {
    Failure::new(
        "provider_error",
        "protocol",
        message.into(),
        true,
        "Supply valid decoded packet records.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
fn resource(message: &str) -> Failure {
    Failure::new(
        "resource_constraint",
        "memory",
        message.into(),
        true,
        "Reduce the capture or decoded record set and retry.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
