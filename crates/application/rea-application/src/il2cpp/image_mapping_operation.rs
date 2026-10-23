//! Captured IL2CPP native-image mapping.
//!
//! This operation accepts a caller-owned byte snapshot and projects the
//! format-neutral image mapper into JSON. It never opens paths or infers a
//! Mach-O layout when the checked mapper cannot establish one.

use crate::il2cpp::image_mapping::{
    self, AddressRange, Error, FormatDetails, ImageFormat, NormalizedImage, NormalizedSegment,
};
use crate::il2cpp::macho_fat_image::{
    FatArchitectureRequest, FatArchitectureSelection, FatClass, FatEndian, FatImage, FatSlice,
    SliceStatus,
};
use crate::il2cpp::macho_image::MachOImage;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

// Keep the application projection aligned with the public runtime contract.
// The operation is a read-only inspection even though its implementation
// performs address mapping internally.
pub const OPERATION: &str = "inspect_il2cpp_image";
const MAX_CAPTURE_BYTES: usize = 256 * 1024 * 1024;
const MAX_PATH_BYTES: usize = 4096;

/// Decode and project one caller-supplied native image snapshot.
pub fn project(input: &Value) -> Result<Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("Input must be an object"))?;
    reject_unknown_fields(object)?;

    let bytes = decode_capture_bytes(object)?;
    if bytes.is_empty() || bytes.len() > MAX_CAPTURE_BYTES {
        return Err(invalid(
            "Captured image bytes are empty or exceed the limit",
        ));
    }

    let digest = format!("{:x}", Sha256::digest(&bytes));
    if let Some(expected) = object.get("sha256") {
        let expected = expected
            .as_str()
            .ok_or_else(|| invalid("sha256 must be a lowercase hexadecimal digest"))?;
        if expected.len() != 64
            || !expected
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(invalid("sha256 must be a lowercase hexadecimal digest"));
        }
        if expected != digest {
            return Err(invalid("sha256 does not match the captured image bytes"));
        }
    }
    if let Some(path_value) = object.get("path") {
        let path = path_value
            .as_str()
            .ok_or_else(|| invalid("path must be a non-empty NUL-free string"))?;
        if path.is_empty() || path.len() > MAX_PATH_BYTES || path.contains('\0') {
            return Err(invalid(
                "path must be non-empty, NUL-free, and at most 4096 bytes",
            ));
        }
    }

    let architecture = parse_architecture_request(object)?;

    let artifact = json!({
        "path": object.get("path").cloned().unwrap_or(Value::Null),
        "sha256": digest,
        "byte_count": bytes.len(),
    });

    if let Some(fat_projection) = project_fat_image(&bytes, artifact.clone(), architecture)? {
        return Ok(fat_projection);
    }

    match image_mapping::map_image(&bytes) {
        Ok(image) => Ok(project_mapped(image, artifact)),
        Err(Error::UnsupportedFormat) => Ok(unsupported(artifact, "unsupported-format", vec![])),
        Err(Error::MachOMapperUnavailable) => project_macho_image(&bytes, artifact, 0),
        Err(error) => Err(mapping_failure(
            format!("Native image mapping failed: {error}"),
            &artifact,
        )),
    }
}

fn project_macho_image(
    bytes: &[u8],
    artifact: Value,
    file_offset_base: u64,
) -> Result<Value, Failure> {
    let image = MachOImage::parse(bytes).map_err(|error| {
        mapping_failure(format!("Native image mapping failed: {error}"), &artifact)
    })?;
    let segments = image
        .segments()
        .iter()
        .enumerate()
        .map(|(index, segment)| {
            let file_offset = file_offset_base
                .checked_add(segment.file_range.start)
                .ok_or_else(|| {
                    mapping_failure("Mach-O segment file offset overflows".into(), &artifact)
                })?;

            Ok(NormalizedSegment {
                index,
                name: segment_name(&segment.name),
                file_offset,
                file_size: segment.file_range.end - segment.file_range.start,
                virtual_address: segment.vm_range.start,
                virtual_size: segment.vm_range.end - segment.vm_range.start,
                readable: Some(segment.initial_protections.readable),
                writable: Some(segment.initial_protections.writable),
                executable: segment.initial_protections.executable,
                format_details: FormatDetails::MachO {
                    raw_name: segment.name.to_vec(),
                    protections: Some(segment.initial_protections.raw),
                },
            })
        })
        .collect::<Result<Vec<_>, Failure>>()?;
    let executable_ranges = image
        .segments()
        .iter()
        .filter(|segment| segment.initial_protections.executable)
        .map(|segment| AddressRange {
            start: segment.vm_range.start,
            end: segment.vm_range.end,
        })
        .collect::<Vec<_>>();
    let image_base = image
        .segments()
        .iter()
        .map(|segment| segment.vm_range.start)
        .min();

    Ok(project_mapped(
        NormalizedImage {
            format: ImageFormat::MachO,
            architecture: u64::from(image.cpu().cpu_type),
            image_base,
            segments,
            executable_ranges,
            limitations: vec![
                "Addresses are file-image virtual addresses; runtime load bias is unknown".into(),
                "Mach-O segment names retain raw bytes in format_details; display names use lossless UTF-8 replacement".into(),
            ],
        },
        artifact,
    ))
}

fn segment_name(raw_name: &[u8; 16]) -> Option<String> {
    let end = raw_name
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(raw_name.len());
    (!raw_name[..end].is_empty()).then(|| String::from_utf8_lossy(&raw_name[..end]).into_owned())
}

fn project_fat_image(
    bytes: &[u8],
    artifact: Value,
    architecture: Option<FatArchitectureRequest>,
) -> Result<Option<Value>, Failure> {
    if !has_fat_magic(bytes) {
        return Ok(None);
    }

    match FatImage::parse(bytes) {
        Ok(image) => Ok(Some(project_fat(image, bytes, artifact, architecture)?)),
        Err(crate::il2cpp::macho_fat_image::Error::UnsupportedMagic(_)) => Ok(None),
        Err(error) => Ok(Some(unsupported(
            artifact,
            "macho-fat-container-invalid",
            vec![format!(
                "Unable to parse universal Mach-O container: {error}"
            )],
        ))),
    }
}

fn has_fat_magic(bytes: &[u8]) -> bool {
    let Some(raw_magic) = bytes.get(..4) else {
        return false;
    };

    matches!(
        u32::from_be_bytes(raw_magic.try_into().expect("four-byte FAT magic")),
        0xcafe_babe | 0xbeba_feca | 0xcafe_babf | 0xbfba_feca
    )
}

fn project_fat(
    image: FatImage,
    bytes: &[u8],
    artifact: Value,
    architecture: Option<FatArchitectureRequest>,
) -> Result<Value, Failure> {
    if let Some(request) = architecture {
        return match image
            .select_requested_architecture(bytes, Some(request))
            .map_err(|error| {
                mapping_failure(
                    format!("Mach-O architecture selection failed: {error}"),
                    &artifact,
                )
            })? {
            FatArchitectureSelection::Selected(view) => {
                let mut projection =
                    project_macho_image(view.bytes, artifact, view.slice.range.offset)?;
                if let Some(object) = projection.as_object_mut() {
                    object
                        .get_mut("limitations")
                        .and_then(Value::as_array_mut)
                        .expect("mapped Mach-O projection has limitations")
                        .push(json!(format!(
                            "Selected FAT slice {} for cputype {} cpusubtype {}",
                            view.slice.index, request.cpu_type, request.cpu_subtype
                        )));
                }
                Ok(projection)
            }
            FatArchitectureSelection::Unknown => {
                unreachable!("an architecture request was supplied")
            }
            FatArchitectureSelection::Ambiguous { indices } => Ok(unsupported(
                artifact,
                "macho-fat-architecture-ambiguous",
                vec![format!(
                    "Requested architecture matches multiple FAT slices: {indices:?}"
                )],
            )),
            FatArchitectureSelection::Absent {
                cpu_type,
                cpu_subtype,
            } => Ok(unsupported(
                artifact,
                "macho-fat-architecture-absent",
                vec![format!(
                    "Requested architecture cputype {cpu_type} cpusubtype {cpu_subtype} is absent"
                )],
            )),
        };
    }

    let segments = image
        .slices
        .iter()
        .map(|slice| project_fat_slice(slice, bytes))
        .collect::<Vec<_>>();

    Ok(json!({
        "operation": OPERATION,
        "status": "unsupported",
        "artifact": artifact,
        "format": "macho",
        "architecture": Value::Null,
        "image_base": Value::Null,
        "segments": segments,
        "executable_ranges": [],
        "limitations": [
            "Universal Mach-O slices were parsed as candidates, but no architecture was selected",
            "Each segment entry describes one FAT slice candidate rather than a mapped thin-image segment",
            format!("FAT class: {}; byte order: {}", fat_class(image.class), fat_endian(image.endian)),
        ],
    }))
}

fn project_fat_slice(slice: &FatSlice, bytes: &[u8]) -> Value {
    let thin = thin_slice_details(slice, bytes);
    let status = slice.status.iter().map(slice_status).collect::<Vec<_>>();

    json!({
        "index": slice.index,
        "name": format!("fat-slice-{}", slice.index),
        "file_offset": slice.range.offset,
        "file_size": slice.range.size,
        "virtual_address": 0,
        "virtual_size": 0,
        "readable": false,
        "writable": false,
        "executable": false,
        "format_details": {
            "format": "macho-fat-slice",
            "cpu_type": slice.cpu_type,
            "cpu_subtype": slice.cpu_subtype,
            "alignment_power": slice.alignment_power,
            "reserved": slice.reserved,
            "status": status,
            "thin_image": thin,
        },
    })
}

fn thin_slice_details(slice: &FatSlice, bytes: &[u8]) -> Value {
    let Some((start, end)) = bounded_slice(slice, bytes.len()) else {
        return json!({ "status": "not_attempted", "reason": "slice-range-is-not-readable" });
    };

    match MachOImage::parse(&bytes[start..end]) {
        Ok(image) => json!({
            "status": "parsed",
            "class": format!("{:?}", image.class()),
            "endian": format!("{:?}", image.endian()),
            "cpu_type": image.cpu().cpu_type,
            "cpu_subtype": image.cpu().cpu_subtype,
            "file_type": image.file_type(),
            "flags": image.flags(),
            "segment_count": image.segments().len(),
        }),
        Err(error) => json!({
            "status": "invalid",
            "reason": error.to_string(),
        }),
    }
}

fn bounded_slice(slice: &FatSlice, file_length: usize) -> Option<(usize, usize)> {
    let start = usize::try_from(slice.range.offset).ok()?;
    let size = usize::try_from(slice.range.size).ok()?;
    let end = start.checked_add(size)?;
    (end <= file_length).then_some((start, end))
}

fn fat_class(class: FatClass) -> &'static str {
    match class {
        FatClass::Fat32 => "fat32",
        FatClass::Fat64 => "fat64",
    }
}

fn fat_endian(endian: FatEndian) -> &'static str {
    match endian {
        FatEndian::Big => "big",
        FatEndian::Little => "little",
    }
}

fn slice_status(status: &SliceStatus) -> Value {
    match status {
        SliceStatus::Valid => json!("valid"),
        SliceStatus::Empty => json!("empty"),
        SliceStatus::OutOfBounds => json!("out-of-bounds"),
        SliceStatus::Overflow => json!("overflow"),
        SliceStatus::OverlapsHeader => json!("overlaps-header"),
        SliceStatus::UnsupportedAlignment { maximum } => {
            json!({ "kind": "unsupported-alignment", "maximum_alignment_power": maximum })
        }
        SliceStatus::Misaligned { required } => {
            json!({ "kind": "misaligned", "required_alignment_power": required })
        }
        SliceStatus::Overlaps { other_index } => {
            json!({ "kind": "overlaps", "other_index": other_index })
        }
        SliceStatus::DuplicateArchitecture { other_index } => {
            json!({ "kind": "duplicate-architecture", "other_index": other_index })
        }
    }
}

fn project_mapped(image: NormalizedImage, artifact: Value) -> Value {
    let segment_count = image.segments.len();
    let executable_range_count = image.executable_ranges.len();
    let mut limitations = image.limitations;
    limitations.push(format!(
        "Captured mapping coverage includes {} segments and {} executable ranges",
        segment_count, executable_range_count
    ));

    json!({
        "operation": OPERATION,
        "status": "mapped",
        "artifact": artifact,
        "format": image_format(image.format),
        "architecture": image.architecture.to_string(),
        "image_base": image.image_base,
        "segments": image.segments.into_iter().map(|segment| {
            json!({
                "index": segment.index,
                "name": segment.name,
                "file_offset": segment.file_offset,
                "file_size": segment.file_size,
                "virtual_address": segment.virtual_address,
                "virtual_size": segment.virtual_size,
                "readable": segment.readable,
                "writable": segment.writable,
                "executable": segment.executable,
                "format_details": format_details(segment.format_details),
            })
        }).collect::<Vec<_>>(),
        "executable_ranges": image.executable_ranges.into_iter().map(|range| {
            json!({ "start": range.start, "end": range.end })
        }).collect::<Vec<_>>(),
        "limitations": limitations,
    })
}

fn unsupported(artifact: Value, reason: &str, additional_limitations: Vec<String>) -> Value {
    let mut limitations = vec![reason.to_string()];
    limitations.extend(additional_limitations);
    limitations.push("No format or address facts were inferred from the capture".into());

    json!({
        "operation": OPERATION,
        "status": "unsupported",
        "artifact": artifact,
        "format": Value::Null,
        "architecture": Value::Null,
        "image_base": Value::Null,
        "segments": [],
        "executable_ranges": [],
        "limitations": limitations,
    })
}

fn image_format(format: ImageFormat) -> &'static str {
    match format {
        ImageFormat::Elf => "elf",
        ImageFormat::MachO => "macho",
        ImageFormat::Pe => "pe",
    }
}

fn format_details(details: FormatDetails) -> Value {
    match details {
        FormatDetails::Elf { flags, alignment } => json!({
            "format": "elf",
            "flags": flags,
            "alignment": alignment,
        }),
        FormatDetails::Pe {
            characteristics,
            section_name,
        } => json!({
            "format": "pe",
            "characteristics": characteristics,
            "section_name_base64": STANDARD.encode(section_name),
        }),
        FormatDetails::MachO {
            raw_name,
            protections,
        } => json!({
            "format": "macho",
            "raw_name_base64": STANDARD.encode(raw_name),
            "protections": protections,
        }),
    }
}

fn reject_unknown_fields(object: &Map<String, Value>) -> Result<(), Failure> {
    for field in object.keys() {
        if !matches!(
            field.as_str(),
            "bytes_base64" | "bytes" | "path" | "sha256" | "architecture"
        ) {
            return Err(invalid(&format!("Unknown input field: {field}")));
        }
    }
    Ok(())
}

fn decode_capture_bytes(object: &Map<String, Value>) -> Result<Vec<u8>, Failure> {
    let encoded = match (object.get("bytes_base64"), object.get("bytes")) {
        (Some(_), Some(_)) => {
            return Err(invalid(
                "supply only one byte representation: bytes_base64 or bytes",
            ));
        }
        (Some(value), None) | (None, Some(value)) => value
            .as_str()
            .ok_or_else(|| invalid("bytes_base64 must contain a Base64 string"))?,
        (None, None) => return Err(invalid("bytes_base64 is required")),
    };

    STANDARD
        .decode(encoded)
        .map_err(|_| invalid("bytes_base64 must contain valid Base64"))
}

fn parse_architecture_request(
    object: &Map<String, Value>,
) -> Result<Option<FatArchitectureRequest>, Failure> {
    let Some(value) = object.get("architecture") else {
        return Ok(None);
    };
    let architecture = value
        .as_object()
        .ok_or_else(|| invalid("architecture must contain cpu_type and cpu_subtype"))?;
    let cpu_type = architecture
        .get("cpu_type")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| invalid("architecture.cpu_type must be a uint32"))?;
    let cpu_subtype = architecture
        .get("cpu_subtype")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| invalid("architecture.cpu_subtype must be a uint32"))?;
    Ok(Some(FatArchitectureRequest {
        cpu_type,
        cpu_subtype,
    }))
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.into(),
        false,
        "Provide a bounded captured native image and retry.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

fn mapping_failure(reason: String, artifact: &Value) -> Failure {
    let mut failure = invalid(&reason);
    if let Err(retain_error) = failure.retain(artifact) {
        failure.detail(
            "partial_observation_error",
            Detail::Text(format!("Unable to retain image identity: {retain_error}")),
        );
    }
    failure
}
