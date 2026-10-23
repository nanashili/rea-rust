//! File-backed CIL method-body decoding and projection.
//!
//! Port of `src/dotnet/ManagedMethodBodyReader.ts`. Tiny and fat headers are
//! read, IL extents are bounded against file-backed section data, the decoded
//! instructions and exception regions are retained, and unavailable
//! implementations (native, runtime, P/Invoke) are reported as partial.

use serde_json::{Map, Value};

use super::budget::admit_managed_projection;
use super::bytes::{read_u8, read_u16, read_u32};
use super::exception_validation::validate_exception_region_ranges;
use super::failure::{InternalFailure, ManagedReaderFailure, ReadError};
use super::heaps::sha256_bytes;
use super::instruction_decoder::{
    DecodedInstructions, ExceptionRegionParseResult, ParsedInstruction, decode_instructions,
    normalized_tuples_json, opcode_counts, parse_exception_regions,
};
use super::layout::ManagedMetadataLayout;
use super::pe_reader::ManagedPeLayout;

/// A decoded anchor retained for edge/user-string derivation.
#[derive(Clone)]
pub struct Anchor {
    pub opcode: &'static str,
    pub operand_kind: &'static str,
    pub operand: Option<String>,
}

/// A decoded method body ready for projection and edge derivation.
pub struct MethodBody {
    pub status: &'static str,
    pub value: Value,
    pub anchors: Vec<Anchor>,
}

/// The method body plus whether every instruction was decoded.
pub struct MethodBodyRead {
    pub body: MethodBody,
    pub scanned: bool,
}

fn body_status(
    decoded_issue: &Option<String>,
    truncated: i64,
    exception_regions: Option<&ExceptionRegionParseResult>,
) -> &'static str {
    let eh_malformed = matches!(
        exception_regions,
        Some(ExceptionRegionParseResult::Malformed { .. })
    );
    if decoded_issue.is_some() || eh_malformed {
        return "malformed";
    }
    if truncated > 0 {
        return "partial";
    }
    "present"
}

struct MethodBodyHeader {
    format: &'static str,
    size: i64,
    flags: i64,
    max_stack: i64,
    il_size: i64,
    local_sig: i64,
}

fn read_method_body_header(bytes: &[u8], offset: i64) -> Result<MethodBodyHeader, InternalFailure> {
    let first = read_u8(bytes, offset as usize)?;
    if (first & 3) == 2 {
        return Ok(MethodBodyHeader {
            format: "tiny",
            size: 1,
            flags: 0,
            max_stack: 8,
            il_size: (first >> 2) as i64,
            local_sig: 0,
        });
    }
    if (first & 3) != 3 {
        return Err(InternalFailure(
            "Unsupported method body header".to_string(),
        ));
    }
    if offset > bytes.len() as i64 - 12 {
        return Err(InternalFailure(
            "Fat method body header leaves artifact".to_string(),
        ));
    }
    let flags_and_size = read_u16(bytes, offset as usize)?;
    let header_dwords = (flags_and_size >> 12) as i64;
    if header_dwords < 3 {
        return Err(InternalFailure(
            "Fat method body header is smaller than 12 bytes".to_string(),
        ));
    }
    let size = header_dwords * 4;
    if offset > bytes.len() as i64 - size {
        return Err(InternalFailure(
            "Method body header leaves artifact".to_string(),
        ));
    }
    Ok(MethodBodyHeader {
        format: "fat",
        size,
        flags: (flags_and_size & 0x0fff) as i64,
        max_stack: read_u16(bytes, (offset + 2) as usize)? as i64,
        il_size: read_u32(bytes, (offset + 4) as usize)? as i64,
        local_sig: read_u32(bytes, (offset + 8) as usize)? as i64,
    })
}

fn empty_body_value(rva: i64, status: &str, issue: Option<&str>) -> Value {
    let mut map = Map::new();
    map.insert("status".into(), Value::from(status));
    map.insert(
        "header_format".into(),
        Value::from(if status == "absent" {
            "none"
        } else {
            "unknown"
        }),
    );
    map.insert("rva".into(), Value::from(rva));
    map.insert("file_offset".into(), Value::Null);
    map.insert("max_stack".into(), Value::Null);
    map.insert("init_locals".into(), Value::Null);
    map.insert("local_var_sig_token".into(), Value::Null);
    map.insert("il_size".into(), Value::from(0));
    map.insert("il_sha256".into(), Value::Null);
    map.insert("normalized_il_sha256".into(), Value::Null);
    map.insert("instruction_count".into(), Value::from(0));
    map.insert("decoded_instruction_count".into(), Value::from(0));
    map.insert("truncated_instructions".into(), Value::from(0));
    map.insert("opcode_counts".into(), Value::Object(Map::new()));
    map.insert("anchors".into(), Value::Array(Vec::new()));
    map.insert("exception_regions".into(), Value::Array(Vec::new()));
    map.insert(
        "issue".into(),
        match issue {
            Some(issue) => Value::from(issue),
            None => Value::Null,
        },
    );
    Value::Object(map)
}

fn empty_body(rva: i64, status: &'static str, issue: Option<&str>) -> MethodBody {
    MethodBody {
        status,
        value: empty_body_value(rva, status, issue),
        anchors: Vec::new(),
    }
}

/// `methodBody(bytes, pe, rva, implementation, budget)`. The shared decode
/// budget is reached through `layout`, matching the TS single shared budget.
pub fn method_body(
    bytes: &[u8],
    pe: &ManagedPeLayout,
    layout: &ManagedMetadataLayout,
    rva: i64,
    impl_flags: i64,
    flags: i64,
) -> Result<MethodBodyRead, ReadError> {
    if rva == 0 {
        return Ok(MethodBodyRead {
            body: empty_body(rva, "absent", None),
            scanned: true,
        });
    }
    let native = (impl_flags & 7) != 0 || (flags & 0x2000) != 0;
    if native {
        let issue = "CIL decoding is unavailable for native, runtime, unmanaged, or P/Invoke implementations";
        return Ok(MethodBodyRead {
            body: empty_body(rva, "partial", Some(issue)),
            scanned: true,
        });
    }

    let result = decode_body(bytes, pe, layout, rva);
    // Transient IL/exception bookkeeping always ends with the body.
    layout.budget().release_transient();
    match result {
        Ok(read) => Ok(read),
        Err(DecodeStop::ResourceLimit(failure)) => Err(ReadError::Reader(failure)),
        Err(DecodeStop::Malformed(message)) => Ok(MethodBodyRead {
            body: empty_body(rva, "malformed", Some(&message)),
            scanned: false,
        }),
    }
}

enum DecodeStop {
    ResourceLimit(ManagedReaderFailure),
    Malformed(String),
}

fn decode_body(
    bytes: &[u8],
    pe: &ManagedPeLayout,
    layout: &ManagedMetadataLayout,
    rva: i64,
) -> Result<MethodBodyRead, DecodeStop> {
    let offset = pe
        .rva_to_offset(bytes, rva, 1, "method.body")
        .map_err(reader_to_stop)?;
    let method_extent = pe
        .rva_available_bytes(bytes, rva, "method.body")
        .map_err(reader_to_stop)?;
    let header = read_method_body_header(bytes, offset).map_err(|e| DecodeStop::Malformed(e.0))?;
    if header.size > method_extent || header.il_size > method_extent - header.size {
        return Err(DecodeStop::Malformed(
            "Method body leaves file-backed PE section data".to_string(),
        ));
    }
    let il_offset = offset + header.size;
    if il_offset > bytes.len() as i64 - header.il_size {
        return Err(DecodeStop::Malformed(
            "Method IL bytes leave artifact".to_string(),
        ));
    }
    let il = &bytes[il_offset as usize..(il_offset + header.il_size) as usize];

    let mut admit_error: Option<ManagedReaderFailure> = None;
    let decoded: DecodedInstructions = {
        let mut admit = |start: i64| -> Result<(), ManagedReaderFailure> {
            layout
                .budget()
                .admit_transient(256, Some((il_offset + start) as u64))
        };
        match decode_instructions(il, Some(&mut admit)) {
            Ok(decoded) => decoded,
            Err(failure) => {
                admit_error = Some(failure);
                DecodedInstructions {
                    parsed: Vec::new(),
                    instruction_starts: Vec::new(),
                    count: 0,
                    truncated: 0,
                    issue: None,
                }
            }
        }
    };
    if let Some(failure) = admit_error {
        return Err(DecodeStop::ResourceLimit(failure));
    }

    let opcode_counts_value = opcode_counts(&decoded.parsed);
    let anchors: Vec<Anchor> = decoded
        .parsed
        .iter()
        .filter(|instruction| instruction.operand_kind != "none")
        .map(|instruction| Anchor {
            opcode: instruction.opcode,
            operand_kind: instruction.operand_kind,
            operand: instruction.operand.clone(),
        })
        .collect();

    let normalized = normalized_tuples_json(&decoded.parsed);

    let method_end = il_offset + header.il_size;
    let section_offset = ceil_div4(method_end) * 4;
    let exception_regions = if header.format == "fat" && (header.flags & 8) != 0 {
        let parsed = {
            let mut guard = layout.budget();
            parse_exception_regions(
                bytes,
                section_offset,
                offset + method_extent,
                Some(&mut guard),
            )
        };
        match parsed {
            Ok(parsed) => Some(validate_exception_region_ranges(
                parsed,
                header.il_size,
                &decoded.instruction_starts,
            )),
            Err(failure) => return Err(reader_to_stop_from(failure)),
        }
    } else {
        None
    };

    let status = body_status(
        &decoded.issue,
        decoded.truncated,
        exception_regions.as_ref(),
    );

    let il_sha256 = sha256_bytes(il);
    let normalized_il_sha256 = if status == "present" {
        Some(sha256_bytes(&normalized))
    } else {
        None
    };

    let issue = decoded
        .issue
        .clone()
        .or_else(|| {
            exception_regions
                .as_ref()
                .and_then(|regions| regions.issue().map(|s| s.to_string()))
        })
        .or_else(|| {
            if decoded.truncated > 0 {
                Some("Instruction decoding stopped before the end of the method body".to_string())
            } else {
                None
            }
        });

    let body_value = build_body_value(BodyFields {
        status,
        header_format: header.format,
        rva,
        file_offset: Some(offset),
        max_stack: Some(header.max_stack),
        init_locals: Some((header.flags & 0x10) != 0),
        local_var_sig_token: if header.local_sig == 0 {
            None
        } else {
            Some(format!("0x{:08x}", header.local_sig))
        },
        il_size: header.il_size,
        il_sha256: Some(il_sha256),
        normalized_il_sha256,
        instruction_count: decoded.count,
        decoded_instruction_count: decoded.parsed.len() as i64,
        truncated_instructions: decoded.truncated,
        opcode_counts: opcode_counts_value,
        anchors: &decoded.parsed,
        exception_regions: exception_regions
            .as_ref()
            .map(|regions| regions.regions())
            .unwrap_or(&[]),
        issue,
    });

    {
        let mut guard = layout.budget();
        admit_managed_projection(&body_value, Some(&mut guard))
            .map_err(DecodeStop::ResourceLimit)?;
    }

    let scanned = decoded.issue.is_none() && decoded.truncated == 0;
    Ok(MethodBodyRead {
        body: MethodBody {
            status,
            value: body_value,
            anchors,
        },
        scanned,
    })
}

struct BodyFields<'a> {
    status: &'static str,
    header_format: &'static str,
    rva: i64,
    file_offset: Option<i64>,
    max_stack: Option<i64>,
    init_locals: Option<bool>,
    local_var_sig_token: Option<String>,
    il_size: i64,
    il_sha256: Option<String>,
    normalized_il_sha256: Option<String>,
    instruction_count: i64,
    decoded_instruction_count: i64,
    truncated_instructions: i64,
    opcode_counts: Map<String, Value>,
    anchors: &'a [ParsedInstruction],
    exception_regions: &'a [super::instruction_decoder::ManagedExceptionRegion],
    issue: Option<String>,
}

fn build_body_value(fields: BodyFields<'_>) -> Value {
    let mut map = Map::new();
    map.insert("status".into(), Value::from(fields.status));
    map.insert("header_format".into(), Value::from(fields.header_format));
    map.insert("rva".into(), Value::from(fields.rva));
    map.insert("file_offset".into(), opt_i64(fields.file_offset));
    map.insert("max_stack".into(), opt_i64(fields.max_stack));
    map.insert(
        "init_locals".into(),
        match fields.init_locals {
            Some(value) => Value::from(value),
            None => Value::Null,
        },
    );
    map.insert(
        "local_var_sig_token".into(),
        opt_string(fields.local_var_sig_token),
    );
    map.insert("il_size".into(), Value::from(fields.il_size));
    map.insert("il_sha256".into(), opt_string(fields.il_sha256));
    map.insert(
        "normalized_il_sha256".into(),
        opt_string(fields.normalized_il_sha256),
    );
    map.insert(
        "instruction_count".into(),
        Value::from(fields.instruction_count),
    );
    map.insert(
        "decoded_instruction_count".into(),
        Value::from(fields.decoded_instruction_count),
    );
    map.insert(
        "truncated_instructions".into(),
        Value::from(fields.truncated_instructions),
    );
    map.insert("opcode_counts".into(), Value::Object(fields.opcode_counts));
    let anchors: Vec<Value> = fields
        .anchors
        .iter()
        .filter(|instruction| instruction.operand_kind != "none")
        .map(|instruction| {
            let mut anchor = Map::new();
            anchor.insert("il_offset".into(), Value::from(instruction.offset));
            anchor.insert("opcode".into(), Value::from(instruction.opcode));
            anchor.insert("operand_kind".into(), Value::from(instruction.operand_kind));
            anchor.insert(
                "operand".into(),
                match &instruction.operand {
                    Some(operand) => Value::from(operand.clone()),
                    None => Value::Null,
                },
            );
            Value::Object(anchor)
        })
        .collect();
    map.insert("anchors".into(), Value::Array(anchors));
    map.insert(
        "exception_regions".into(),
        Value::Array(
            fields
                .exception_regions
                .iter()
                .map(|r| r.to_value())
                .collect(),
        ),
    );
    map.insert("issue".into(), opt_string(fields.issue));
    Value::Object(map)
}

fn opt_i64(value: Option<i64>) -> Value {
    match value {
        Some(value) => Value::from(value),
        None => Value::Null,
    }
}

fn opt_string(value: Option<String>) -> Value {
    match value {
        Some(value) => Value::from(value),
        None => Value::Null,
    }
}

fn ceil_div4(value: i64) -> i64 {
    (value + 3).div_euclid(4)
}

fn reader_to_stop(failure: ManagedReaderFailure) -> DecodeStop {
    reader_to_stop_from(failure)
}

fn reader_to_stop_from(failure: ManagedReaderFailure) -> DecodeStop {
    if failure.issue.code == "resource-limit" {
        DecodeStop::ResourceLimit(failure)
    } else {
        DecodeStop::Malformed(failure.issue.detail)
    }
}
