//! Parse capinfos metadata and tshark `-T json` field output.
//!
//! Compatibility owner: `src/pcap/PcapOutput.ts`. capinfos is read under a C
//! locale so numbers are exact; timestamps are projected to RFC 3339 UTC.
//! The tshark JSON representation is bounded before and during decoding, then
//! aggregated into the fixed capture inventory.
use crate::pcap::order::compare_code_points;
use crate::pcap::url::{self, Credentials};
use rea_core::analysis_error::AnalysisError;
use rea_core::cancellation::Cancellation;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet};

const OPERATION: &str = "inspect_pcap_capture";

/// Bounds JSON decoding plus its expanded object graph before parsing.
pub const TSHARK_JSON_MAX_BYTES: usize = 8 * 1024 * 1024;
const MAX_RETAINED_BYTES: u64 = 16 * 1024 * 1024;
const MAX_DECODED_BYTES: u64 = 128 * 1024 * 1024;

fn protocol_failure(reason: &str) -> AnalysisError {
    AnalysisError::protocol(format!("Invalid packet-capture output: {reason}"))
}

/// Parsed capinfos metadata.
#[derive(Clone, Debug)]
pub struct CapinfosMetadata {
    pub file_type: String,
    pub encapsulation: String,
    pub packet_count: u64,
    pub capture_start: Option<String>,
    pub capture_end: Option<String>,
    pub capture_duration_seconds: Option<f64>,
    pub snapshot_length: Option<u64>,
    pub sha256: Option<String>,
}

/// Civil date (year, month, day) from days since 1970-01-01.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// capinfos timestamp projection to RFC 3339 UTC, keeping fractional digits.
///
/// Compatibility owner: `captureInstant` in `src/pcap/PcapOutput.ts`.
fn capture_instant(value: Option<&str>) -> Option<String> {
    let text = value.unwrap_or("");
    // `^(-?)(\d{1,20})(?:\.(\d{1,9}))?$`
    let bytes = text.as_bytes();
    let mut index = 0;
    let negative = bytes.first() == Some(&b'-');
    if negative {
        index += 1;
    }
    let seconds_start = index;
    while index < bytes.len() && bytes[index].is_ascii_digit() {
        index += 1;
    }
    let seconds_digits = index - seconds_start;
    if seconds_digits == 0 || seconds_digits > 20 {
        return None;
    }
    let seconds_text = &text[seconds_start..index];
    let mut fraction = String::new();
    if index < bytes.len() {
        if bytes[index] != b'.' {
            return None;
        }
        index += 1;
        let frac_start = index;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
        }
        let frac_digits = index - frac_start;
        if frac_digits == 0 || frac_digits > 9 || index != bytes.len() {
            return None;
        }
        fraction = text[frac_start..index].to_owned();
    }

    let mut seconds: i128 = seconds_text.parse::<i128>().ok()?;
    if negative {
        let digits = fraction.len();
        let fraction_value: i128 = if digits > 0 {
            fraction.parse::<i128>().ok()?
        } else {
            0
        };
        let borrowed = digits > 0 && fraction_value > 0;
        seconds = -seconds - if borrowed { 1 } else { 0 };
        if borrowed {
            let base = 10_i128.pow(digits as u32);
            let adjusted = base - fraction_value;
            fraction = format!("{adjusted:0width$}", width = digits);
        }
    }

    if seconds < -62_167_219_200 || seconds > 253_402_300_799 {
        return None;
    }

    // Date from seconds since epoch (UTC).
    let secs = seconds as i64;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    if year < 0 || year > 9999 {
        return None;
    }
    let hour = rem / 3_600;
    let minute = (rem % 3_600) / 60;
    let second = rem % 60;
    let base = format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}");
    Some(if fraction.is_empty() {
        format!("{base}Z")
    } else {
        format!("{base}.{fraction}Z")
    })
}

/// capinfos `-M -S` with a C locale.
///
/// Compatibility owner: `parseCapinfosOutput`.
pub fn parse_capinfos_output(stdout: &str) -> Result<CapinfosMetadata, AnalysisError> {
    let mut lines: HashMap<String, String> = HashMap::new();
    for line in stdout
        .split('\n')
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
    {
        if let Some(at) = line.find(':')
            && !line.starts_with([' ', '\t'])
        {
            lines.insert(line[..at].to_owned(), line[at + 1..].trim().to_owned());
        }
    }
    let file_type = lines.get("File type").filter(|value| !value.is_empty());
    let encapsulation = lines
        .get("File encapsulation")
        .filter(|value| !value.is_empty());
    let count_text = lines.get("Number of packets");
    let count_ok = count_text
        .is_some_and(|text| !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()));
    let (Some(file_type), Some(encapsulation), true) = (file_type, encapsulation, count_ok) else {
        return Err(protocol_failure(
            "capinfos did not provide machine-readable type, encapsulation and packet count",
        ));
    };
    let packet_count: u64 = count_text
        .expect("count present")
        .parse()
        .map_err(|_| protocol_failure("packet count is not representable"))?;
    if packet_count > 9_007_199_254_740_991 {
        return Err(protocol_failure("packet count is not representable"));
    }

    let duration = lines
        .get("Capture duration")
        .and_then(|text| parse_duration_seconds(text));

    let snapshot_length = lines
        .get("Packet size limit")
        .and_then(|text| parse_snapshot_length(text))
        .filter(|&value| value > 0 && value <= 9_007_199_254_740_991);

    let sha256 = lines.get("SHA256").cloned();
    if let Some(sha256) = &sha256
        && !(sha256.len() == 64
            && sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()))
    {
        return Err(protocol_failure("capinfos SHA256 is malformed"));
    }

    let capture_start = capture_instant(
        lines
            .get("Earliest packet time")
            .or_else(|| lines.get("First packet time"))
            .map(String::as_str),
    );
    let capture_end = capture_instant(
        lines
            .get("Latest packet time")
            .or_else(|| lines.get("Last packet time"))
            .map(String::as_str),
    );

    Ok(CapinfosMetadata {
        file_type: file_type.clone(),
        encapsulation: encapsulation.clone(),
        packet_count,
        capture_start,
        capture_end,
        capture_duration_seconds: duration,
        snapshot_length,
        sha256,
    })
}

/// `^(\d+(?:\.\d+)?)(?:\s+seconds?)?$` -> the leading numeric value.
fn parse_duration_seconds(text: &str) -> Option<f64> {
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() && bytes[index].is_ascii_digit() {
        index += 1;
    }
    if index == 0 {
        return None;
    }
    if index < bytes.len() && bytes[index] == b'.' {
        let frac_start = index + 1;
        index += 1;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
        }
        if index == frac_start {
            return None;
        }
    }
    let number = &text[..index];
    let rest = &text[index..];
    let rest_ok = rest.is_empty() || {
        let trimmed = rest.trim_start();
        rest.len() != trimmed.len() && (trimmed == "second" || trimmed == "seconds")
    };
    if !rest_ok {
        return None;
    }
    number.parse::<f64>().ok()
}

/// `^file hdr:\s*(\d+) bytes$` -> the byte count.
fn parse_snapshot_length(text: &str) -> Option<u64> {
    let rest = text.strip_prefix("file hdr:")?;
    let rest = rest.trim_start();
    let digits_end = rest
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(rest.len());
    if digits_end == 0 {
        return None;
    }
    let digits = &rest[..digits_end];
    if rest[digits_end..] != *" bytes" {
        return None;
    }
    digits.parse::<u64>().ok()
}

/// Aggregated tshark field inventory.
#[derive(Clone, Debug, Default)]
pub struct TsharkFields {
    pub endpoints: Vec<(String, u64)>,
    pub endpoint_count: u64,
    pub dns_queries: Vec<(String, Vec<String>)>,
    pub dns_query_count: u64,
    pub tls_sni_values: Vec<String>,
    pub tls_sni_count: u64,
    pub protocol_distribution: Vec<(String, u64)>,
    pub protocol_count: u64,
    pub http_request_uris: Vec<String>,
    pub http_request_uri_count: u64,
    pub http_uri_redaction_count: u64,
    pub unattributed_dns_addresses: Vec<String>,
    pub unattributed_dns_address_count: u64,
    pub unattributed_dns_packets: u64,
    pub packet_count: u64,
    pub partial: bool,
}

/// Insertion-ordered set of strings with code-point tiebreak counting.
#[derive(Default)]
struct OrderedSet {
    order: Vec<String>,
    index: HashSet<String>,
}
impl OrderedSet {
    fn insert(&mut self, value: &str) -> bool {
        if self.index.contains(value) {
            false
        } else {
            self.index.insert(value.to_owned());
            self.order.push(value.to_owned());
            true
        }
    }
    fn contains(&self, value: &str) -> bool {
        self.index.contains(value)
    }
    fn len(&self) -> usize {
        self.order.len()
    }
}

/// Insertion-ordered counting map.
#[derive(Default)]
struct OrderedCounts {
    order: Vec<String>,
    counts: HashMap<String, u64>,
}
impl OrderedCounts {
    fn bump(&mut self, key: &str) -> bool {
        match self.counts.get_mut(key) {
            Some(count) => {
                *count += 1;
                false
            }
            None => {
                self.counts.insert(key.to_owned(), 1);
                self.order.push(key.to_owned());
                true
            }
        }
    }
    fn sorted(&self) -> Vec<(String, u64)> {
        let mut entries: Vec<(String, u64)> = self
            .order
            .iter()
            .map(|key| (key.clone(), self.counts[key]))
            .collect();
        entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| compare_code_points(&a.0, &b.0)));
        entries
    }
}

struct RetainedBudget {
    bytes: u64,
}
impl RetainedBudget {
    fn charge(&mut self, value: &str) -> Result<(), AnalysisError> {
        self.bytes += 192 + 2 * value.len() as u64;
        if self.bytes > MAX_RETAINED_BYTES {
            return Err(AnalysisError::resource_constraint(
                OPERATION,
                "memory",
                "Packet inventory exceeds the retained-fact budget",
                Some(serde_json::json!({ "max_retained_bytes": MAX_RETAINED_BYTES })),
            ));
        }
        Ok(())
    }
}

fn layer_strings<'a>(layers: &'a serde_json::Map<String, Value>, name: &str) -> Vec<&'a str> {
    layers
        .get(name)
        .and_then(Value::as_array)
        .map(|values| values.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

/// Validate and aggregate the tshark JSON field representation.
///
/// Compatibility owner: `parseTsharkJsonOutput`.
pub fn parse_tshark_json_output(
    stdout: &str,
    cancellation: &Cancellation,
) -> Result<TsharkFields, AnalysisError> {
    if cancellation.reason().is_some() {
        return Err(AnalysisError::cancelled(OPERATION));
    }
    if stdout.len() > TSHARK_JSON_MAX_BYTES {
        return Err(AnalysisError::resource_constraint(
            OPERATION,
            "memory",
            "tshark JSON exceeds the bounded decoding budget",
            Some(serde_json::json!({ "max_json_bytes": TSHARK_JSON_MAX_BYTES })),
        ));
    }

    // Bound structural depth and expanded graph before materializing.
    let mut depth: i64 = 0;
    let mut quoted = false;
    let mut escaped = false;
    let mut decoded_bytes: u64 = stdout.len() as u64 * 2;
    for (index, character) in stdout.bytes().enumerate() {
        if index % 65_536 == 0 && cancellation.reason().is_some() {
            return Err(AnalysisError::cancelled(OPERATION));
        }
        if quoted {
            if escaped {
                escaped = false;
            } else if character == b'\\' {
                escaped = true;
            } else if character == b'"' {
                quoted = false;
            }
        } else if character == b'"' {
            quoted = true;
            decoded_bytes += 64;
        } else if character == b'{' || character == b'[' {
            decoded_bytes += 128;
            depth += 1;
            if depth > 5 {
                return Err(protocol_failure("unexpected JSON nesting"));
            }
        } else if character == b'}' || character == b']' {
            depth -= 1;
        } else if character == b':' || character == b',' {
            decoded_bytes += 128;
        }
        if decoded_bytes > MAX_DECODED_BYTES {
            return Err(AnalysisError::resource_constraint(
                OPERATION,
                "memory",
                "tshark JSON expansion exceeds the decoding budget",
                Some(serde_json::json!({ "max_decoded_bytes": MAX_DECODED_BYTES })),
            ));
        }
    }

    let packets: Value = serde_json::from_str(stdout).map_err(|error| {
        AnalysisError::protocol(format!("tshark emitted malformed JSON ({error})"))
    })?;
    let Value::Array(packets) = packets else {
        return Err(protocol_failure("tshark packet root must be an array"));
    };

    let mut endpoints = OrderedCounts::default();
    let mut dns: BTreeMap<String, usize> = BTreeMap::new();
    let mut dns_order: Vec<String> = Vec::new();
    let mut dns_values: Vec<OrderedSet> = Vec::new();
    let mut sni = OrderedSet::default();
    let mut protocols = OrderedCounts::default();
    let mut uris = OrderedSet::default();
    let mut observed_uris = OrderedSet::default();
    let mut uri_redactions: u64 = 0;
    let mut unattributed = OrderedSet::default();
    let mut unattributed_packets: u64 = 0;
    let mut budget = RetainedBudget { bytes: 0 };

    for (index, packet) in packets.iter().enumerate() {
        if index % 256 == 0 && cancellation.reason().is_some() {
            return Err(AnalysisError::cancelled(OPERATION));
        }
        let layers = packet
            .get("_source")
            .and_then(|source| source.get("layers"))
            .and_then(Value::as_object);
        let Some(layers) = layers else {
            return Err(protocol_failure(&format!(
                "packet {} lacks _source.layers",
                index + 1
            )));
        };
        for (key, value) in layers {
            let strings_only = value
                .as_array()
                .is_some_and(|values| values.iter().all(Value::is_string));
            if !strings_only {
                return Err(protocol_failure(&format!(
                    "packet {} field {key} must be an array of strings",
                    index + 1
                )));
            }
        }

        let frame = layer_strings(layers, "frame.number");
        let frame_ok = frame.len() == 1
            && !frame[0].is_empty()
            && frame[0].bytes().all(|byte| byte.is_ascii_digit())
            && frame[0].parse::<u64>().ok() == Some((index + 1) as u64);
        if !frame_ok {
            return Err(protocol_failure(
                "frame inventory is missing, duplicated or out of order",
            ));
        }

        let protocols_field = layer_strings(layers, "frame.protocols");
        if protocols_field.len() != 1 || protocols_field[0].is_empty() {
            return Err(protocol_failure(
                "packet protocol inventory is missing or ambiguous",
            ));
        }

        // Count one occurrence per packet even for loopback or nested layers.
        let mut address_set: Vec<&str> = Vec::new();
        for name in ["ip.src", "ip.dst", "ipv6.src", "ipv6.dst"] {
            for address in layer_strings(layers, name) {
                if !address_set.contains(&address) {
                    address_set.push(address);
                }
            }
        }
        for address in address_set {
            if address.is_empty() {
                continue;
            }
            if !endpoints.counts.contains_key(address) {
                budget.charge(address)?;
            }
            endpoints.bump(address);
        }

        let mut questions: Vec<&str> = Vec::new();
        for question in layer_strings(layers, "dns.qry.name") {
            if !question.is_empty() && !questions.contains(&question) {
                questions.push(question);
            }
        }
        for question in &questions {
            if !dns.contains_key(*question) {
                budget.charge(question)?;
                dns.insert((*question).to_owned(), dns_values.len());
                dns_order.push((*question).to_owned());
                dns_values.push(OrderedSet::default());
            }
        }

        let mut addresses: Vec<&str> = Vec::new();
        for name in ["dns.a", "dns.aaaa"] {
            for address in layer_strings(layers, name) {
                if !address.is_empty() {
                    addresses.push(address);
                }
            }
        }
        let response = layer_strings(layers, "dns.flags.response");
        if !addresses.is_empty() {
            let attributed = questions.len() == 1
                && !response.is_empty()
                && response
                    .iter()
                    .all(|value| *value == "True" || *value == "1");
            if attributed {
                let slot = dns[questions[0]];
                for address in &addresses {
                    if !dns_values[slot].contains(address) {
                        budget.charge(address)?;
                        dns_values[slot].insert(address);
                    }
                }
            } else {
                unattributed_packets += 1;
                for address in &addresses {
                    if !unattributed.contains(address) {
                        budget.charge(address)?;
                        unattributed.insert(address);
                    }
                }
            }
        }

        for value in layer_strings(layers, "tls.handshake.extensions_server_name") {
            if !value.is_empty() && !sni.contains(value) {
                budget.charge(value)?;
                sni.insert(value);
            }
        }

        let mut seen_protocols: Vec<&str> = Vec::new();
        for value in layer_strings(layers, "frame.protocols") {
            if !seen_protocols.contains(&value) {
                seen_protocols.push(value);
            }
        }
        for value in seen_protocols {
            if value.is_empty() {
                continue;
            }
            if !protocols.counts.contains_key(value) {
                budget.charge(value)?;
            }
            protocols.bump(value);
        }

        for value in layer_strings(layers, "http.request.full_uri") {
            if value.is_empty() || observed_uris.contains(value) {
                continue;
            }
            if !observed_uris.contains(value) {
                budget.charge(value)?;
                observed_uris.insert(value);
            }
            match url::credentials(value) {
                Credentials::None => {
                    if !uris.contains(value) {
                        budget.charge(value)?;
                        uris.insert(value);
                    }
                }
                Credentials::Ambiguous => {
                    uri_redactions += 1;
                }
                Credentials::Span { start, end } => {
                    uri_redactions += 1;
                    let redacted = format!("{}{}", &value[..start], &value[end..]);
                    if !uris.contains(&redacted) {
                        budget.charge(&redacted)?;
                        uris.insert(&redacted);
                    }
                }
            }
        }
    }

    if cancellation.reason().is_some() {
        return Err(AnalysisError::cancelled(OPERATION));
    }

    let dns_queries: Vec<(String, Vec<String>)> = dns_order
        .iter()
        .map(|query| {
            let slot = dns[query];
            (query.clone(), dns_values[slot].order.clone())
        })
        .collect();

    Ok(TsharkFields {
        endpoints: endpoints.sorted(),
        endpoint_count: endpoints.order.len() as u64,
        dns_query_count: dns_order.len() as u64,
        dns_queries,
        tls_sni_count: sni.len() as u64,
        tls_sni_values: sni.order.clone(),
        protocol_distribution: protocols.sorted(),
        protocol_count: protocols.order.len() as u64,
        http_request_uri_count: observed_uris.len() as u64,
        http_request_uris: uris.order.clone(),
        http_uri_redaction_count: uri_redactions,
        unattributed_dns_address_count: unattributed.len() as u64,
        unattributed_dns_addresses: unattributed.order.clone(),
        unattributed_dns_packets: unattributed_packets,
        packet_count: packets.len() as u64,
        partial: observed_uris.len() > uris.len() || unattributed_packets > 0,
    })
}
