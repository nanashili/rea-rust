//! Explicit-layout decoder for a captured IL2CPP `CodeGenModule` record.
//!
//! Unity changes registration layouts between versions and platforms.  This
//! module therefore accepts offsets and byte order from the caller and never
//! guesses a layout from a byte pattern.

use base64::Engine;
use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub const OPERATION: &str = "inspect_il2cpp_codegen_module_layout";
const MAX_RECORD_BYTES: usize = 4096;
const MAX_NAME_BYTES: usize = 4096;
const MAX_POINTERS: u64 = 200_000;

/// Decode one caller-supplied record and its optional pointed-to captures.
///
/// Required fields are `layout` and `record_bytes_base64`. The layout must
/// provide `version`, `pointer_width`, `endianness`, and explicit offsets for
/// the three fields. A name capture and pointer-table capture are supplied
/// separately because this decoder does not dereference process addresses.
/// Missing pointed-to bytes remain explicit incomplete facts in the normalized
/// output rather than being represented as fabricated empty captures.
pub fn parse(input: &Value) -> Result<Value, Failure> {
    let root = input
        .as_object()
        .ok_or_else(|| invalid("input", "Expected an object"))?;
    let layout = root
        .get("layout")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("layout", "An explicit layout descriptor is required"))?;
    let record = decode(
        root.get("record_bytes_base64"),
        "record_bytes_base64",
        MAX_RECORD_BYTES,
    )?;
    let descriptor = Layout::parse(layout, record.len())?;

    let name_pointer =
        descriptor.read_pointer(&record, descriptor.name_pointer_offset, "name_pointer")?;
    let method_count = descriptor.read_integer(
        &record,
        descriptor.method_pointer_count_offset,
        descriptor.method_pointer_count_width,
        "method_pointer_count",
    )?;
    let method_table_pointer = descriptor.read_pointer(
        &record,
        descriptor.method_pointers_offset,
        "method_pointers",
    )?;
    if method_count > MAX_POINTERS {
        return Err(invalid(
            "method_pointer_count",
            "Pointer count exceeds the bounded limit",
        ));
    }
    let name = decode_name(root.get("name_bytes_base64"), name_pointer)?;
    let pointers = decode_pointer_table(
        root.get("method_pointers_bytes_base64"),
        method_count,
        descriptor.pointer_width,
        descriptor.endianness,
        method_table_pointer,
    )?;
    let method_pointer_slots =
        project_method_pointer_slots(root.get("method_pointer_mappings"), &pointers)?;
    let module_name = root
        .get("module_name")
        .and_then(Value::as_str)
        .map(str::to_owned);
    if module_name
        .as_deref()
        .is_some_and(|name| name.chars().count() > MAX_NAME_BYTES)
    {
        return Err(invalid(
            "module_name",
            "Declared module name exceeds the bounded limit",
        ));
    }
    if let (Some(captured), Some(declared)) = (&name, &module_name) {
        if captured != declared {
            return Err(invalid(
                "module_name",
                "Declared and captured module names disagree",
            ));
        }
    }

    Ok(serde_json::json!({
        "operation": OPERATION,
        "layout": descriptor.to_value(),
        "module_name": module_name.or(name),
        "name_pointer": name_pointer,
        "method_pointer_count": method_count,
        "method_pointers": pointers,
        "method_pointer_slots": method_pointer_slots,
        "method_pointers_pointer": method_table_pointer,
        "source": { "record_bytes": record.len(), "pointer_table_captured": root.get("method_pointers_bytes_base64").is_some() }
    }))
}

/// Add mapping provenance without changing the raw pointer-table rows.
///
/// The raw table is intentionally retained as the capture's primary fact.
/// This projection is a separate, typed interpretation: zero-valued slots
/// remain `zero_filled`, one matching mapping is `resolved`, and competing or
/// absent mappings remain explicit rather than selecting a likely address.
fn project_method_pointer_slots(
    mappings: Option<&Value>,
    pointers: &Value,
) -> Result<Value, Failure> {
    let Some(rows) = pointers.as_array() else {
        return Ok(Value::Null);
    };
    let mappings = parse_pointer_mappings(mappings)?;
    let mut projected = Vec::with_capacity(rows.len());

    for row in rows {
        let slot = row
            .get("slot")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid("method_pointers", "Pointer row has no slot"))?;
        let address = row
            .get("address")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid("method_pointers", "Pointer row has no address"))?;

        if address == 0 {
            projected.push(serde_json::json!({
                "slot": slot,
                "address": address,
                "resolution": "zero_filled",
                "target_file_offset": Value::Null,
                "mapping": Value::Null,
            }));
            continue;
        }

        let matches = mappings
            .iter()
            .filter_map(|mapping| mapping.match_address(address))
            .collect::<Vec<_>>();
        match matches.as_slice() {
            [] => projected.push(serde_json::json!({
                "slot": slot,
                "address": address,
                "resolution": "unmapped",
                "target_file_offset": Value::Null,
                "mapping": Value::Null,
            })),
            [mapping] => projected.push(serde_json::json!({
                "slot": slot,
                "address": address,
                "resolution": "resolved",
                "target_file_offset": mapping.file_offset,
                "mapping": mapping.provenance.clone(),
            })),
            _ => projected.push(serde_json::json!({
                "slot": slot,
                "address": address,
                "resolution": "ambiguous",
                "target_file_offset": Value::Null,
                "mapping": Value::Null,
                "mapping_candidates": matches
                    .iter()
                    .map(|mapping| mapping.provenance.clone())
                    .collect::<Vec<_>>(),
            })),
        }
    }

    Ok(Value::Array(projected))
}

#[derive(Clone)]
struct PointerMapping {
    virtual_start: u64,
    virtual_end: u64,
    file_start: u64,
    file_end: u64,
    provenance: Value,
}

struct MatchedMapping {
    file_offset: u64,
    provenance: Value,
}

impl PointerMapping {
    fn match_address(&self, address: u64) -> Option<MatchedMapping> {
        if address < self.virtual_start || address >= self.virtual_end {
            return None;
        }
        let file_offset = self.file_start.checked_add(address - self.virtual_start)?;
        (file_offset < self.file_end).then_some(MatchedMapping {
            file_offset,
            provenance: self.provenance.clone(),
        })
    }
}

fn parse_pointer_mappings(value: Option<&Value>) -> Result<Vec<PointerMapping>, Failure> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let rows = value
        .as_array()
        .ok_or_else(|| invalid("method_pointer_mappings", "Expected an array"))?;
    if (rows.len() as u64) > MAX_POINTERS {
        return Err(invalid(
            "method_pointer_mappings",
            "Mapping collection exceeds the bounded limit",
        ));
    }

    rows.iter()
        .enumerate()
        .map(|(index, row)| {
            let object = row.as_object().ok_or_else(|| {
                invalid(
                    &format!("method_pointer_mappings[{index}]"),
                    "Expected an object",
                )
            })?;
            let virtual_start = mapping_number(object, "virtual_start", index)?;
            let virtual_end = mapping_number(object, "virtual_end", index)?;
            let file_start = mapping_number(object, "file_start", index)?;
            let file_end = mapping_number(object, "file_end", index)?;
            if virtual_start >= virtual_end || file_start >= file_end {
                return Err(invalid(
                    &format!("method_pointer_mappings[{index}]"),
                    "Mapping ranges must be non-empty and ordered",
                ));
            }
            Ok(PointerMapping {
                virtual_start,
                virtual_end,
                file_start,
                file_end,
                provenance: serde_json::json!({
                    "index": index,
                    "virtual_start": virtual_start,
                    "virtual_end": virtual_end,
                    "file_start": file_start,
                    "file_end": file_end,
                }),
            })
        })
        .collect()
}

fn mapping_number(object: &Map<String, Value>, field: &str, index: usize) -> Result<u64, Failure> {
    number(
        object.get(field),
        &format!("method_pointer_mappings[{index}].{field}"),
    )
}

#[derive(Clone)]
struct Layout {
    version: u64,
    record_size: usize,
    pointer_width: usize,
    method_pointer_count_width: usize,
    endianness: Endian,
    name_pointer_offset: usize,
    method_pointer_count_offset: usize,
    method_pointers_offset: usize,
}

#[derive(Clone, Copy)]
enum Endian {
    Little,
    Big,
}

impl Layout {
    fn parse(value: &Map<String, Value>, captured_record_size: usize) -> Result<Self, Failure> {
        validate_layout_fields(value)?;

        let version = number(value.get("version"), "layout.version")?;

        // The public layout contract contains only the fields needed to
        // decode the captured record.  The capture adapter may provide
        // internal bookkeeping fields, so derive their defaults at this
        // boundary while still validating explicitly supplied values.
        if let Some(variant) = value.get("variant") {
            if variant
                .as_str()
                .is_none_or(|variant| variant.trim().is_empty())
            {
                return Err(invalid(
                    "layout.variant",
                    "An explicit layout variant must be non-empty text",
                ));
            }
        }

        let record_size = value
            .get("record_size")
            .map(|_| offset(value, "record_size"))
            .transpose()?
            .unwrap_or(captured_record_size);
        if record_size == 0 || record_size > MAX_RECORD_BYTES {
            return Err(invalid(
                "layout.record_size",
                "Record size must be within the bounded capture limit",
            ));
        }
        if captured_record_size != record_size {
            return Err(invalid(
                "record_bytes_base64",
                "Captured record size does not match layout.record_size",
            ));
        }

        let pointer_width =
            usize::try_from(number(value.get("pointer_width"), "layout.pointer_width")?)
                .map_err(|_| invalid("layout.pointer_width", "Pointer width does not fit usize"))?;
        let pointer_width = match pointer_width {
            4 | 8 => pointer_width,
            _ => {
                return Err(invalid(
                    "layout.pointer_width",
                    "Pointer width must be 4 or 8",
                ));
            }
        };
        let method_pointer_count_width = value
            .get("method_pointer_count_width")
            .map(|value| {
                usize::try_from(number(Some(value), "layout.method_pointer_count_width")?).map_err(
                    |_| {
                        invalid(
                            "layout.method_pointer_count_width",
                            "Count width does not fit usize",
                        )
                    },
                )
            })
            .transpose()?
            // `Il2CppCodeGenModule::methodPointerCount` is a uint32_t on
            // the supported layouts, independently of pointer width.
            .unwrap_or(4);
        let method_pointer_count_width = match method_pointer_count_width {
            4 => method_pointer_count_width,
            _ => {
                return Err(invalid(
                    "layout.method_pointer_count_width",
                    "Count width must be 4 bytes for Il2CppCodeGenModule::methodPointerCount",
                ));
            }
        };
        let endianness = match value.get("endianness").and_then(Value::as_str) {
            Some("little") => Endian::Little,
            Some("big") => Endian::Big,
            _ => {
                return Err(invalid(
                    "layout.endianness",
                    "Endianness must be little or big",
                ));
            }
        };
        let name_pointer_offset = offset(value, "name_pointer_offset")?;
        let method_pointer_count_offset = offset(value, "method_pointer_count_offset")?;
        let method_pointers_offset = offset(value, "method_pointers_offset")?;

        validate_field_bounds(
            record_size,
            name_pointer_offset,
            pointer_width,
            "layout.name_pointer_offset",
        )?;
        validate_field_bounds(
            record_size,
            method_pointer_count_offset,
            method_pointer_count_width,
            "layout.method_pointer_count_offset",
        )?;
        validate_field_bounds(
            record_size,
            method_pointers_offset,
            pointer_width,
            "layout.method_pointers_offset",
        )?;
        validate_non_overlapping_fields(
            name_pointer_offset,
            pointer_width,
            method_pointer_count_offset,
            method_pointer_count_width,
            method_pointers_offset,
            pointer_width,
        )?;

        Ok(Self {
            version,
            record_size,
            pointer_width,
            method_pointer_count_width,
            endianness,
            name_pointer_offset,
            method_pointer_count_offset,
            method_pointers_offset,
        })
    }

    fn read_integer(
        &self,
        bytes: &[u8],
        offset: usize,
        width: usize,
        field: &str,
    ) -> Result<u64, Failure> {
        let end = offset
            .checked_add(width)
            .ok_or_else(|| invalid(field, "Offset overflows"))?;
        let slice = bytes
            .get(offset..end)
            .ok_or_else(|| invalid(field, "Field exceeds captured record bytes"))?;
        Ok(read_integer(slice, width, self.endianness))
    }

    fn read_pointer(&self, bytes: &[u8], offset: usize, field: &str) -> Result<u64, Failure> {
        self.read_integer(bytes, offset, self.pointer_width, field)
    }

    fn to_value(self) -> Value {
        serde_json::json!({
            "version": self.version,
            "pointer_width": self.pointer_width,
            "endianness": match self.endianness { Endian::Little => "little", Endian::Big => "big" },
            "name_pointer_offset": self.name_pointer_offset,
            "method_pointer_count_offset": self.method_pointer_count_offset,
            "method_pointers_offset": self.method_pointers_offset,
        })
    }
}

fn validate_layout_fields(value: &Map<String, Value>) -> Result<(), Failure> {
    const ALLOWED_FIELDS: &[&str] = &[
        "version",
        "variant",
        "record_size",
        "pointer_width",
        "method_pointer_count_width",
        "endianness",
        "name_pointer_offset",
        "method_pointer_count_offset",
        "method_pointers_offset",
    ];

    if let Some(field) = value
        .keys()
        .find(|field| !ALLOWED_FIELDS.contains(&field.as_str()))
    {
        return Err(invalid(&format!("layout.{field}"), "Unknown layout field"));
    }

    Ok(())
}

fn decode_name(value: Option<&Value>, pointer: u64) -> Result<Option<String>, Failure> {
    let Some(value) = value else {
        return Ok(None);
    };
    let bytes = decode(Some(value), "name_bytes_base64", MAX_NAME_BYTES)?;
    let end = bytes.iter().position(|byte| *byte == 0).ok_or_else(|| {
        invalid(
            "name_bytes_base64",
            "C-string capture must contain a NUL terminator",
        )
    })?;
    let name = std::str::from_utf8(&bytes[..end])
        .map_err(|_| invalid("name_bytes_base64", "Module name is not UTF-8"))?;
    if name.is_empty() && pointer != 0 {
        return Err(invalid(
            "name_bytes_base64",
            "Non-null name pointer has an empty module name",
        ));
    }
    if !name.is_empty() && pointer == 0 {
        return Err(invalid(
            "name_bytes_base64",
            "Null name pointer cannot identify a non-empty module name",
        ));
    }
    Ok(Some(name.to_owned()))
}

fn decode_pointer_table(
    value: Option<&Value>,
    count: u64,
    width: usize,
    endian: Endian,
    pointer: u64,
) -> Result<Value, Failure> {
    let Some(value) = value else {
        // The record still gives us an authoritative count and pointer value,
        // but the pointed-to bytes were not retained. Preserve that
        // distinction as `null` instead of fabricating an empty table.
        return Ok(Value::Null);
    };
    let bytes = decode(
        Some(value),
        "method_pointers_bytes_base64",
        MAX_RECORD_BYTES * 1024,
    )?;
    let required = (count as usize)
        .checked_mul(width)
        .ok_or_else(|| invalid("method_pointer_count", "Pointer table size overflows"))?;
    if bytes.len() != required {
        return Err(invalid(
            "method_pointers_bytes_base64",
            "Pointer table capture size does not match method_pointer_count",
        ));
    }

    if count == 0 {
        // A zero-length table has no rows whose ownership could be
        // uncertain.  Preserve the declared complete table even when the
        // ABI represents it with a null pointer.
        return Ok(Value::Array(Vec::new()));
    }

    let mut rows = Vec::with_capacity(count as usize);
    for index in 0..count as usize {
        let start = index * width;
        let address = read_integer(&bytes[start..start + width], width, endian);
        rows.push(serde_json::json!({ "slot": index, "address": address }));
    }

    if pointer == 0 {
        // The bytes are captured, but the record does not establish ownership
        // of those rows. Do not expose them as decompilation candidates: a
        // null association is distinct from a missing capture (the caller can
        // still see `pointer_table_captured: true`) and from a valid table
        // containing zero-filled address slots.
        return Ok(Value::Null);
    }

    Ok(Value::Array(rows))
}

fn read_integer(bytes: &[u8], width: usize, endian: Endian) -> u64 {
    match (width, endian) {
        (4, Endian::Little) => u32::from_le_bytes(bytes.try_into().unwrap()) as u64,
        (4, Endian::Big) => u32::from_be_bytes(bytes.try_into().unwrap()) as u64,
        (8, Endian::Little) => u64::from_le_bytes(bytes.try_into().unwrap()),
        (8, Endian::Big) => u64::from_be_bytes(bytes.try_into().unwrap()),
        _ => unreachable!("layout widths are validated before decoding"),
    }
}

fn validate_field_bounds(
    record_size: usize,
    offset: usize,
    width: usize,
    field: &str,
) -> Result<(), Failure> {
    let end = offset
        .checked_add(width)
        .ok_or_else(|| invalid(field, "Field offset overflows"))?;
    if end > record_size {
        return Err(invalid(field, "Field exceeds layout.record_size"));
    }
    // The offset is caller-owned layout data.  Do not impose a host ABI
    // alignment rule here: Unity records may be packed, and the explicit
    // descriptor is the authority for where each field lives.  Bounds are
    // still checked above against both the declared record and its capture.
    Ok(())
}

fn validate_non_overlapping_fields(
    name_offset: usize,
    name_width: usize,
    count_offset: usize,
    count_width: usize,
    table_offset: usize,
    table_width: usize,
) -> Result<(), Failure> {
    let fields = [
        ("layout.name_pointer_offset", name_offset, name_width),
        (
            "layout.method_pointer_count_offset",
            count_offset,
            count_width,
        ),
        ("layout.method_pointers_offset", table_offset, table_width),
    ];

    for (index, (left_name, left_offset, left_width)) in fields.iter().enumerate() {
        let left_end = *left_offset + *left_width;
        for (_, right_offset, right_width) in fields.iter().skip(index + 1) {
            let right_end = *right_offset + *right_width;
            if *left_offset < right_end && *right_offset < left_end {
                return Err(invalid(
                    left_name,
                    "Field overlaps another CodeGenModule field",
                ));
            }
        }
    }
    Ok(())
}

fn decode(value: Option<&Value>, field: &str, max: usize) -> Result<Vec<u8>, Failure> {
    let text = value
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(field, "Expected base64 text"))?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(text)
        .map_err(|_| invalid(field, "Invalid base64"))?;
    if bytes.len() > max {
        return Err(invalid(field, "Decoded capture exceeds the bounded limit"));
    }
    Ok(bytes)
}

fn number(value: Option<&Value>, field: &str) -> Result<u64, Failure> {
    value
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid(field, "Expected a non-negative integer"))
}
fn offset(value: &Map<String, Value>, field: &str) -> Result<usize, Failure> {
    usize::try_from(number(value.get(field), &format!("layout.{field}"))?)
        .map_err(|_| invalid(&format!("layout.{field}"), "Offset does not fit usize"))
}
fn invalid(field: &str, reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "IL2CPP CodeGenModule layout input is invalid.".into(),
        false,
        "Provide an explicit versioned layout and bounded captures.".into(),
        BTreeMap::from([
            ("operation".into(), Detail::Text(OPERATION.into())),
            ("field".into(), Detail::Text(field.into())),
            ("reason".into(), Detail::Text(reason.into())),
        ]),
    )
}
