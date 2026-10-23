//! Signature-blob decoding, type rendering, type ranges, and name digests.
//!
//! Port of `src/dotnet/ManagedMemberInspectorCore.ts`. Decoding keeps an
//! explicit continuation stack (signatures nest arbitrarily deep), renders each
//! ECMA-335 type form exactly as the TS does, and computes the
//! `resolved_sha256` type-names-v1 digest by replacing each embedded type
//! operand with a `0xff` marker and the operand's resolved name digest.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use super::failure::{
    ManagedParseIssue, ManagedReaderFailure, ReadError, ReadResult, managed_failure,
    read_managed_value,
};
use super::heaps::{
    metadata_coded_token, metadata_coded_token_invalid_reason, metadata_row_cursor, metadata_token,
    read_metadata_string, sha256_bytes,
};
use super::layout::ManagedMetadataLayout;
use super::member_pointers::member_list_table;
use super::type_member_lists::TypeMemberListFacts;
use super::type_nesting::{ManagedTypeNesting, read_managed_type_nesting};

/// One TypeDef's token, full name, and member-list coordinates.
#[derive(Clone)]
pub struct TypeRange {
    pub token: String,
    pub full_name: Option<String>,
    pub field_start: Option<i64>,
    pub field_end: Option<i64>,
    pub method_start: Option<i64>,
    pub method_end: Option<i64>,
}

/// Name/declaring-type facts keyed by token for uniform edge resolution.
#[derive(Clone)]
pub struct MemberCore {
    pub token: String,
    pub name: String,
    pub declaring_type: Option<String>,
    /// `method` | `field` | `unknown`, matching the signature kind.
    pub kind: &'static str,
    /// Generic arity from the owner's decoded signature; `None` when no owner
    /// decoded it (the TS `undefined`), `Some(None)` when decoded to no arity.
    pub generic_arity: Option<Option<i64>>,
}

/// A fully decoded type as its rendered string and the next cursor.
struct RenderedType {
    value: String,
    next: i64,
}

/// A parsed TypeDef row projected into the member result.
pub struct ParsedType {
    pub token: String,
    pub row_offset: i64,
    pub namespace: String,
    pub name: String,
    pub full_name: String,
    pub flags: i64,
    pub extends_token: Option<String>,
    pub enclosing_type_token: Option<String>,
    pub field_list: RowRange,
    pub method_list: RowRange,
}

/// Field/method list window for a type.
pub struct RowRange {
    pub first: Option<i64>,
    pub last: Option<i64>,
    pub count: i64,
}

/// Output of `parseTypes`.
pub struct ParsedTypes {
    pub types: Vec<ParsedType>,
    pub issues: Vec<ManagedParseIssue>,
    pub nesting: ManagedTypeNesting,
}

fn row_range(table_rows: i64, start: Option<i64>, end: Option<i64>) -> RowRange {
    match (start, end) {
        (Some(start), Some(end)) => {
            let last_exclusive = end.min(table_rows + 1);
            if start >= last_exclusive {
                RowRange {
                    first: None,
                    last: None,
                    count: 0,
                }
            } else {
                RowRange {
                    first: Some(start),
                    last: Some(last_exclusive - 1),
                    count: last_exclusive - start,
                }
            }
        }
        _ => RowRange {
            first: None,
            last: None,
            count: 0,
        },
    }
}

/// `fullName(namespace, name)`.
pub fn full_name(namespace: &str, name: &str) -> String {
    if namespace.is_empty() {
        name.to_string()
    } else {
        format!("{namespace}.{name}")
    }
}

fn read_type_range(
    bytes: &[u8],
    layout: &ManagedMetadataLayout,
    row: i64,
    issues: &mut Vec<ManagedParseIssue>,
    member_lists: &TypeMemberListFacts,
) -> ReadResult<TypeRange> {
    let mut cursor = metadata_row_cursor(bytes, layout, 2, row)?;
    cursor.read_u32()?;
    let name_index = cursor.read_index(layout.string_index_size)?;
    let namespace_index = cursor.read_index(layout.string_index_size)?;
    let declared_name = read_managed_value(
        || -> ReadResult<String> {
            let namespace =
                read_metadata_string(bytes, layout, namespace_index, layout.strings.size)?;
            let name = read_metadata_string(bytes, layout, name_index, layout.strings.size)?;
            Ok(full_name(&namespace, &name))
        },
        issues,
    )?;
    cursor.read_index(layout.coded_index_size("TypeDefOrRef"))?;
    let current = member_lists.entries.get((row - 1) as usize);
    Ok(TypeRange {
        token: metadata_token(2, row),
        full_name: declared_name,
        field_start: current.and_then(|entry| entry.field.start.value),
        field_end: current.and_then(|entry| entry.field.end),
        method_start: current.and_then(|entry| entry.method.start.value),
        method_end: current.and_then(|entry| entry.method.end),
    })
}

/// `typeRanges(bytes, layout, issues, memberLists)`.
pub fn type_ranges(
    bytes: &[u8],
    layout: &ManagedMetadataLayout,
    issues: &mut Vec<ManagedParseIssue>,
    member_lists: &TypeMemberListFacts,
) -> ReadResult<Vec<TypeRange>> {
    issues.extend(member_lists.issues.iter().cloned());
    let type_rows = layout.table(2).map(|t| t.row_count).unwrap_or(0);
    let mut ranges = Vec::new();
    for row in 1..=type_rows {
        ranges.push(read_type_range(bytes, layout, row, issues, member_lists)?);
    }
    Ok(ranges)
}
/// `parseTypes(bytes, layout, ranges)`.
pub fn parse_types(
    bytes: &[u8],
    layout: &ManagedMetadataLayout,
    ranges: &[TypeRange],
) -> ReadResult<ParsedTypes> {
    let type_rows = layout.table(2).map(|t| t.row_count).unwrap_or(0);
    let fields_rows = member_list_table(layout, 4)
        .map(|t| t.row_count)
        .unwrap_or(0);
    let methods_rows = member_list_table(layout, 6)
        .map(|t| t.row_count)
        .unwrap_or(0);
    let mut items: Vec<ParsedType> = Vec::new();
    let mut issues: Vec<ManagedParseIssue> = Vec::new();
    let nesting = read_managed_type_nesting(bytes, layout, &mut issues)?;
    for row in 1..=type_rows {
        // Replicate `readManagedValue`: a non-resource reader failure is
        // recorded and the row yields no item; resource-limit and other
        // failures propagate. The Extends issue is pushed inside the fallible
        // section (before the item), exactly as the TS closure does.
        let outcome = parse_type_row(
            bytes,
            layout,
            ranges,
            &nesting,
            fields_rows,
            methods_rows,
            row,
            &mut issues,
        );
        match outcome {
            Ok(item) => items.push(item),
            Err(ReadError::Reader(failure)) => {
                if failure.issue.code == "resource-limit" {
                    return Err(ReadError::Reader(failure));
                }
                issues.push(failure.issue);
            }
            Err(other) => return Err(other),
        }
    }
    Ok(ParsedTypes {
        types: items,
        issues,
        nesting,
    })
}

#[allow(clippy::too_many_arguments)]
fn parse_type_row(
    bytes: &[u8],
    layout: &ManagedMetadataLayout,
    ranges: &[TypeRange],
    nesting: &ManagedTypeNesting,
    fields_rows: i64,
    methods_rows: i64,
    row: i64,
    issues: &mut Vec<ManagedParseIssue>,
) -> ReadResult<ParsedType> {
    let mut cursor = metadata_row_cursor(bytes, layout, 2, row)?;
    let flags = cursor.read_u32()? as i64;
    let name = read_metadata_string(
        bytes,
        layout,
        cursor.read_index(layout.string_index_size)?,
        layout.strings.size,
    )?;
    let namespace = read_metadata_string(
        bytes,
        layout,
        cursor.read_index(layout.string_index_size)?,
        layout.strings.size,
    )?;
    let extends_offset = cursor.offset();
    let extends_raw = cursor.read_index(layout.coded_index_size("TypeDefOrRef"))?;
    let current_range = ranges.get((row - 1) as usize);
    let field_range = row_range(
        fields_rows,
        current_range.and_then(|r| r.field_start),
        current_range.and_then(|r| r.field_end),
    );
    let method_range = row_range(
        methods_rows,
        current_range.and_then(|r| r.method_start),
        current_range.and_then(|r| r.method_end),
    );
    let extends_reason = metadata_coded_token_invalid_reason(
        extends_raw,
        2,
        &[Some(2), Some(1), Some(27)],
        &layout.row_counts,
    );
    if let Some(reason) = &extends_reason {
        issues.push(ManagedParseIssue {
            code: "invalid-row",
            scope: format!("metadata.TypeDef:{}", metadata_token(2, row)),
            offset: Some(extends_offset as u64),
            detail: format!("TypeDef Extends coded index 0x{extends_raw:x} is invalid: {reason}"),
        });
    }
    let enclosing_row = nesting.enclosing.get(&row).copied();
    Ok(ParsedType {
        token: metadata_token(2, row),
        row_offset: cursor.start,
        namespace: namespace.clone(),
        name: name.clone(),
        full_name: full_name(&namespace, &name),
        flags,
        extends_token: metadata_coded_token(
            extends_raw,
            2,
            &[Some(2), Some(1), Some(27)],
            &layout.row_counts,
        ),
        enclosing_type_token: enclosing_row.map(|outer| metadata_token(2, outer)),
        field_list: field_range,
        method_list: method_range,
    })
}

/// `readCompressed(bytes, offset)`.
pub fn read_compressed(bytes: &[u8], offset: i64) -> Result<Compressed, ManagedReaderFailure> {
    let at = offset.max(0) as usize;
    let first = bytes.get(at).copied();
    let first = match first {
        Some(value) => value as i64,
        None => {
            return Err(managed_failure(
                "invalid-blob",
                "signature",
                "truncated compressed integer",
                Some(offset as u64),
            ));
        }
    };
    if (first & 0x80) == 0 {
        return Ok(Compressed {
            value: first,
            next: offset + 1,
        });
    }
    let second = bytes.get(at + 1).copied();
    if (first & 0xc0) == 0x80 {
        if let Some(second) = second {
            return Ok(Compressed {
                value: ((first & 0x3f) << 8) | second as i64,
                next: offset + 2,
            });
        }
    }
    let b1 = bytes.get(at + 1).copied();
    let b2 = bytes.get(at + 2).copied();
    let b3 = bytes.get(at + 3).copied();
    if (first & 0xe0) == 0xc0 {
        if let (Some(b1), Some(b2), Some(b3)) = (b1, b2, b3) {
            return Ok(Compressed {
                value: (first & 0x1f) * 0x01_00_00_00
                    + b1 as i64 * 0x01_00_00
                    + b2 as i64 * 0x0100
                    + b3 as i64,
                next: offset + 4,
            });
        }
    }
    Err(managed_failure(
        "invalid-blob",
        "signature",
        "reserved compressed integer",
        Some(offset as u64),
    ))
}

/// A decoded compressed integer and the next cursor.
pub struct Compressed {
    pub value: i64,
    pub next: i64,
}

fn element_type_name(kind: u8) -> Option<&'static str> {
    match kind {
        0x01 => Some("void"),
        0x02 => Some("bool"),
        0x03 => Some("char"),
        0x04 => Some("i1"),
        0x05 => Some("u1"),
        0x06 => Some("i2"),
        0x07 => Some("u2"),
        0x08 => Some("i4"),
        0x09 => Some("u4"),
        0x0a => Some("i8"),
        0x0b => Some("u8"),
        0x0c => Some("r4"),
        0x0d => Some("r8"),
        0x0e => Some("string"),
        0x18 => Some("native-int"),
        0x19 => Some("native-uint"),
        0x1c => Some("object"),
        _ => None,
    }
}

fn read_signed_compressed(bytes: &[u8], offset: i64) -> Result<Compressed, ManagedReaderFailure> {
    let encoded = read_compressed(bytes, offset)?;
    let width = match encoded.next - offset {
        1 => 7,
        2 => 14,
        _ => 29,
    };
    let magnitude = encoded.value.div_euclid(2);
    let value = if encoded.value % 2 == 0 {
        magnitude
    } else {
        magnitude - (1i64 << (width - 1))
    };
    Ok(Compressed {
        value,
        next: encoded.next,
    })
}

fn malformed_signature(detail: &str, offset: i64) -> ManagedReaderFailure {
    managed_failure(
        "invalid-blob",
        "signature",
        detail.to_string(),
        Some(offset as u64),
    )
}

enum Continuation {
    Suffix(&'static str),
    Modifiers(Vec<String>),
    Array,
    List {
        remaining: i64,
        items: Vec<String>,
        signature_items: bool,
        render: ListRender,
    },
}

enum ListRender {
    Generic { head: String },
    FunctionPointer { head: String },
}

impl ListRender {
    fn render(&self, items: &[String]) -> String {
        match self {
            ListRender::Generic { head } => format!("{head}<{}>", items.join(",")),
            ListRender::FunctionPointer { head } => {
                let return_type = items.first().cloned().unwrap_or_default();
                let parameters = if items.len() > 1 { &items[1..] } else { &[] };
                format!("fnptr[{head}]({})->{return_type}", parameters.join(","))
            }
        }
    }
}

struct MethodSignatureHeader {
    first: u8,
    generic_parameter_count: Option<i64>,
    parameter_count: i64,
    next: i64,
}

fn member_method_header(value: u8) -> bool {
    matches!(value & 0x9f, 0x00 | 0x05 | 0x10)
}

fn function_pointer_convention(value: u8) -> bool {
    matches!(value & 0x0f, 0 | 1 | 2 | 3 | 4 | 5 | 9)
}

fn read_method_signature_header(
    blob: &[u8],
    offset: i64,
    context: &str,
) -> Result<MethodSignatureHeader, ManagedReaderFailure> {
    let first = match blob.get(offset.max(0) as usize).copied() {
        Some(value) => value,
        None => return Err(malformed_signature("truncated method signature", offset)),
    };
    let allowed = if context == "member" {
        member_method_header(first)
    } else {
        (first & 0x80) == 0 && function_pointer_convention(first)
    };
    if !allowed || ((first & 0x40) != 0 && (first & 0x20) == 0) {
        return Err(malformed_signature(
            &format!("calling convention 0x{first:x} does not head a {context} method signature"),
            offset,
        ));
    }
    let mut next = offset + 1;
    let mut generic_parameter_count = None;
    if (first & 0x10) != 0 {
        let generic = read_compressed(blob, next)?;
        generic_parameter_count = Some(generic.value);
        next = generic.next;
    }
    let parameter_count = read_compressed(blob, next)?;
    Ok(MethodSignatureHeader {
        first,
        generic_parameter_count,
        parameter_count: parameter_count.value,
        next: parameter_count.next,
    })
}

const MAX_ARRAY_RANK: i64 = 32;

fn array_shape(blob: &[u8], offset: i64) -> Result<RenderedType, ManagedReaderFailure> {
    let rank = read_compressed(blob, offset)?;
    if rank.value == 0 {
        return Err(malformed_signature("array rank is zero", offset));
    }
    if rank.value > MAX_ARRAY_RANK {
        return Err(managed_failure(
            "unsupported-signature",
            "signature",
            format!(
                "array rank {} exceeds the {MAX_ARRAY_RANK} dimensions the CLR supports",
                rank.value
            ),
            Some(offset as u64),
        ));
    }
    let size_count = read_compressed(blob, rank.next)?;
    if size_count.value > rank.value {
        return Err(malformed_signature(
            "array has more sizes than dimensions",
            offset,
        ));
    }
    let mut sizes: Vec<i64> = Vec::new();
    let mut next = size_count.next;
    for _ in 0..size_count.value {
        let size = read_compressed(blob, next)?;
        sizes.push(size.value);
        next = size.next;
    }
    let bound_count = read_compressed(blob, next)?;
    if bound_count.value > rank.value {
        return Err(malformed_signature(
            "array has more lower bounds than dimensions",
            offset,
        ));
    }
    let mut lower_bounds: Vec<i64> = Vec::new();
    next = bound_count.next;
    for _ in 0..bound_count.value {
        let bound = read_signed_compressed(blob, next)?;
        lower_bounds.push(bound.value);
        next = bound.next;
    }
    let dimensions: Vec<String> = (0..rank.value)
        .map(|index| {
            let size = sizes.get(index as usize).copied();
            let lower = lower_bounds.get(index as usize).copied();
            if let Some(lower) = lower {
                match size {
                    Some(size) => format!("{lower}...{}", lower + size - 1),
                    None => format!("{lower}..."),
                }
            } else if let Some(size) = size {
                size.to_string()
            } else if rank.value == 1 {
                "...".to_string()
            } else {
                String::new()
            }
        })
        .collect();
    Ok(RenderedType {
        value: format!("[{}]", dimensions.join(",")),
        next,
    })
}

#[derive(Clone, Copy, PartialEq)]
enum Position {
    Field,
    Return,
    Parameter,
    Type,
    Pointee,
}

impl Position {
    fn as_str(self) -> &'static str {
        match self {
            Position::Field => "field",
            Position::Return => "return",
            Position::Parameter => "parameter",
            Position::Type => "type",
            Position::Pointee => "pointee",
        }
    }
}

fn current_position(stack: &[Continuation], base: Position) -> Position {
    let frame = stack
        .iter()
        .rev()
        .find(|frame| !matches!(frame, Continuation::Modifiers(_)));
    match frame {
        None => base,
        Some(Continuation::Suffix(suffix)) => {
            if *suffix == "*" {
                Position::Pointee
            } else {
                Position::Type
            }
        }
        Some(Continuation::List {
            signature_items,
            items,
            ..
        }) if *signature_items => {
            if items.is_empty() {
                Position::Return
            } else {
                Position::Parameter
            }
        }
        _ => Position::Type,
    }
}

fn position_elements(kind: u8) -> Option<&'static [Position]> {
    match kind {
        0x01 => Some(&[Position::Return, Position::Pointee]),
        0x16 => Some(&[Position::Return, Position::Parameter]),
        0x10 => Some(&[Position::Return, Position::Parameter, Position::Field]),
        _ => None,
    }
}

/// A TypeDefOrRefOrSpec coded index embedded in a signature blob.
#[derive(Clone)]
pub struct TypeOperand {
    pub offset: i64,
    pub next: i64,
    pub value: i64,
}

fn read_type_operand(
    blob: &[u8],
    offset: i64,
    layout: Option<&ManagedMetadataLayout>,
    tables: &[Option<usize>],
) -> Result<Compressed, ManagedReaderFailure> {
    let token = read_compressed(blob, offset)?;
    if let Some(layout) = layout {
        let reason = if token.value == 0 {
            Some("type operand is null".to_string())
        } else {
            metadata_coded_token_invalid_reason(token.value as u32, 2, tables, &layout.row_counts)
        };
        if let Some(reason) = reason {
            return Err(managed_failure(
                "invalid-row",
                "signature",
                format!(
                    "TypeDefOrRefOrSpec operand 0x{:x} is invalid: {reason}",
                    token.value
                ),
                Some(offset as u64),
            ));
        }
    }
    Ok(token)
}

fn read_type_signature(
    blob: &[u8],
    offset: i64,
    base: Position,
    layout: Option<&ManagedMetadataLayout>,
    operands: Option<&mut Vec<TypeOperand>>,
) -> Result<RenderedType, ManagedReaderFailure> {
    let mut stack: Vec<Continuation> = Vec::new();
    let mut cursor = offset;
    let mut operands = operands;
    loop {
        let mut value: Option<String> = None;
        let kind = match blob.get(cursor.max(0) as usize).copied() {
            Some(kind) => kind,
            None => return Err(malformed_signature("truncated type signature", cursor)),
        };
        if let Some(positions) = position_elements(kind) {
            let here = current_position(&stack, base);
            if !positions.contains(&here) {
                return Err(malformed_signature(
                    &format!(
                        "element type 0x{kind:x} is not valid in a {} position",
                        here.as_str()
                    ),
                    cursor,
                ));
            }
        }
        if let Some(named) = element_type_name(kind) {
            value = Some(named.to_string());
            cursor += 1;
        } else if kind == 0x0f || kind == 0x10 || kind == 0x1d {
            let suffix = if kind == 0x0f {
                "*"
            } else if kind == 0x10 {
                "&"
            } else {
                "[]"
            };
            stack.push(Continuation::Suffix(suffix));
            cursor += 1;
        } else if kind == 0x1f || kind == 0x20 {
            let token = read_type_operand(blob, cursor + 1, layout, &[Some(2), Some(1), Some(27)])?;
            push_operand(&mut operands, cursor + 1, &token);
            let modifier = format!(
                "{}:{}",
                if kind == 0x1f { "modreq" } else { "modopt" },
                token.value
            );
            if let Some(Continuation::Modifiers(modifiers)) = stack.last_mut() {
                modifiers.push(modifier);
            } else {
                stack.push(Continuation::Modifiers(vec![modifier]));
            }
            cursor = token.next;
        } else if kind == 0x11 || kind == 0x12 {
            let token = read_type_operand(blob, cursor + 1, layout, &[Some(2), Some(1), Some(27)])?;
            push_operand(&mut operands, cursor + 1, &token);
            value = Some(format!(
                "{}:{}",
                if kind == 0x11 { "valuetype" } else { "class" },
                token.value
            ));
            cursor = token.next;
        } else if kind == 0x1e || kind == 0x13 {
            let variable = read_compressed(blob, cursor + 1)?;
            value = Some(format!(
                "{}:{}",
                if kind == 0x1e { "mvar" } else { "var" },
                variable.value
            ));
            cursor = variable.next;
        } else if kind == 0x16 {
            value = Some("typedbyref".to_string());
            cursor += 1;
        } else if kind == 0x14 {
            stack.push(Continuation::Array);
            cursor += 1;
        } else if kind == 0x15 {
            let generic = blob.get((cursor + 1).max(0) as usize).copied();
            if generic != Some(0x11) && generic != Some(0x12) {
                return Err(malformed_signature(
                    "generic instantiation does not name a class or value type",
                    cursor + 1,
                ));
            }
            let token = read_type_operand(blob, cursor + 2, layout, &[Some(2), Some(1)])?;
            push_operand(&mut operands, cursor + 2, &token);
            let argument_count = read_compressed(blob, token.next)?;
            if argument_count.value == 0 {
                return Err(malformed_signature(
                    "generic instantiation has no type arguments",
                    token.next,
                ));
            }
            let head = format!(
                "{}:{}",
                if generic == Some(0x11) {
                    "valuetype"
                } else {
                    "class"
                },
                token.value
            );
            stack.push(Continuation::List {
                remaining: argument_count.value,
                items: Vec::new(),
                signature_items: false,
                render: ListRender::Generic { head },
            });
            cursor = argument_count.next;
        } else if kind == 0x1b {
            let header = read_method_signature_header(blob, cursor + 1, "function-pointer")?;
            let convention = calling_convention(header.first);
            let head = match header.generic_parameter_count {
                None => convention,
                Some(count) => format!("{convention};{count}"),
            };
            stack.push(Continuation::List {
                remaining: header.parameter_count + 1,
                items: Vec::new(),
                signature_items: true,
                render: ListRender::FunctionPointer { head },
            });
            cursor = header.next;
        } else {
            return Err(managed_failure(
                "unsupported-signature",
                "signature",
                format!("unsupported element type 0x{kind:x}"),
                Some(cursor as u64),
            ));
        }

        while let Some(current) = value.take() {
            let mut current = current;
            match stack.pop() {
                None => {
                    return Ok(RenderedType {
                        value: current,
                        next: cursor,
                    });
                }
                Some(Continuation::Suffix(suffix)) => {
                    current.push_str(suffix);
                    value = Some(current);
                }
                Some(Continuation::Modifiers(modifiers)) => {
                    current = format!("{current} {}", modifiers.join(" "));
                    value = Some(current);
                }
                Some(Continuation::Array) => {
                    let shape = array_shape(blob, cursor)?;
                    current.push_str(&shape.value);
                    cursor = shape.next;
                    value = Some(current);
                }
                Some(Continuation::List {
                    remaining,
                    mut items,
                    signature_items,
                    render,
                }) => {
                    items.push(current);
                    let remaining = remaining - 1;
                    if remaining == 0 {
                        value = Some(render.render(&items));
                    } else {
                        stack.push(Continuation::List {
                            remaining,
                            items,
                            signature_items,
                            render,
                        });
                        value = None;
                    }
                }
            }
        }
    }
}

fn push_operand(operands: &mut Option<&mut Vec<TypeOperand>>, offset: i64, token: &Compressed) {
    if let Some(operands) = operands {
        operands.push(TypeOperand {
            offset,
            next: token.next,
            value: token.value,
        });
    }
}

fn calling_convention_name(base: i64) -> Option<&'static str> {
    match base {
        0 => Some("default"),
        1 => Some("c"),
        2 => Some("stdcall"),
        3 => Some("thiscall"),
        4 => Some("fastcall"),
        5 => Some("vararg"),
        6 => Some("field"),
        9 => Some("unmanaged"),
        _ => None,
    }
}

fn calling_convention(value: u8) -> String {
    let base = (value & 0x0f) as i64;
    let mut flags: Vec<&str> = Vec::new();
    if (value & 0x20) != 0 {
        flags.push("has-this");
    }
    if (value & 0x40) != 0 {
        flags.push("explicit-this");
    }
    if (value & 0x10) != 0 {
        flags.push("generic");
    }
    let name = calling_convention_name(base)
        .map(|name| name.to_string())
        .unwrap_or_else(|| format!("unknown:{base}"));
    if flags.is_empty() {
        name
    } else {
        format!("{name} {}", flags.join(" "))
    }
}

/// `specSignature(layout, blob, owner)`.
///
/// `form` is `"type"` or `"instantiation"`. Rendering is transient and charged
/// against the layout budget. Malformed/unsupported blobs rethrow under the
/// owner scope and offset.
pub fn spec_signature(
    layout: &ManagedMetadataLayout,
    blob: &[u8],
    form: &str,
    scope: &str,
    offset: i64,
) -> Result<Vec<String>, ManagedReaderFailure> {
    layout
        .budget()
        .admit_transient(blob.len() as i64 * 256, Some(offset as u64))?;
    let outcome = spec_signature_inner(layout, blob, form);
    layout.budget().release_transient();
    match outcome {
        Ok(types) => Ok(types),
        Err(failure) => {
            if failure.issue.code == "invalid-blob"
                || failure.issue.code == "invalid-row"
                || failure.issue.code == "unsupported-signature"
            {
                Err(managed_failure(
                    failure.issue.code,
                    scope.to_string(),
                    failure.issue.detail,
                    Some(offset as u64),
                ))
            } else {
                Err(failure)
            }
        }
    }
}

fn spec_signature_inner(
    layout: &ManagedMetadataLayout,
    blob: &[u8],
    form: &str,
) -> Result<Vec<String>, ManagedReaderFailure> {
    let mut cursor = 0i64;
    let mut count = 1i64;
    if form == "instantiation" {
        if blob.first().copied() != Some(0x0a) {
            return Err(malformed_signature(
                "MethodSpec instantiation is not GENERICINST",
                0,
            ));
        }
        let header = read_compressed(blob, 1)?;
        if header.value == 0 {
            return Err(malformed_signature(
                "MethodSpec instantiation has no type arguments",
                1,
            ));
        }
        count = header.value;
        cursor = header.next;
    }
    let mut types: Vec<String> = Vec::new();
    for _ in 0..count {
        let rendered = read_type_signature(blob, cursor, Position::Type, Some(layout), None)?;
        types.push(rendered.value);
        cursor = rendered.next;
    }
    if cursor != blob.len() as i64 {
        return Err(malformed_signature("Trailing signature data", cursor));
    }
    Ok(types)
}

/// Decoded signature facts (kind, counts, rendered types, issue).
pub struct DecodedSignature {
    pub kind: &'static str,
    pub parse_status: &'static str,
    pub calling_convention: Option<String>,
    pub generic_parameter_count: Option<i64>,
    pub parameter_count: Option<i64>,
    pub return_type: Option<String>,
    pub parameter_types: Vec<String>,
    pub field_type: Option<String>,
    pub issue: Option<String>,
}

fn decode_signature(blob: &[u8], operands: &mut Vec<TypeOperand>) -> DecodedSignature {
    match decode_signature_inner(blob, operands) {
        Ok(decoded) => decoded,
        Err(failure) => {
            // A non-blob/unsupported failure would be rethrown in the TS, but
            // decode is always called where such a failure cannot arise beyond
            // these two codes; map them to kind "unknown".
            DecodedSignature {
                kind: "unknown",
                parse_status: if failure.issue.code == "unsupported-signature" {
                    "unsupported"
                } else {
                    "malformed"
                },
                calling_convention: None,
                generic_parameter_count: None,
                parameter_count: None,
                return_type: None,
                parameter_types: Vec::new(),
                field_type: None,
                issue: Some(failure.issue.detail),
            }
        }
    }
}

fn decode_signature_inner(
    blob: &[u8],
    operands: &mut Vec<TypeOperand>,
) -> Result<DecodedSignature, ManagedReaderFailure> {
    if blob.is_empty() {
        return Err(managed_failure(
            "invalid-blob",
            "signature",
            "empty signature",
            Some(0),
        ));
    }
    let first = blob.first().copied().unwrap_or(0);
    if first == 0x06 {
        let field_type = read_type_signature(blob, 1, Position::Field, None, Some(operands))?;
        let decoded = field_type.next == blob.len() as i64;
        return Ok(DecodedSignature {
            kind: "field",
            parse_status: if decoded { "decoded" } else { "partial" },
            calling_convention: Some(calling_convention(first)),
            generic_parameter_count: None,
            parameter_count: None,
            return_type: None,
            parameter_types: Vec::new(),
            field_type: Some(field_type.value),
            issue: if decoded {
                None
            } else {
                Some("Trailing signature data".to_string())
            },
        });
    }
    let header = read_method_signature_header(blob, 0, "member")?;
    let return_type =
        read_type_signature(blob, header.next, Position::Return, None, Some(operands))?;
    let mut offset = return_type.next;
    let mut parameters: Vec<String> = Vec::new();
    for _ in 0..header.parameter_count {
        let parameter =
            read_type_signature(blob, offset, Position::Parameter, None, Some(operands))?;
        parameters.push(parameter.value);
        offset = parameter.next;
    }
    let decoded = offset == blob.len() as i64;
    Ok(DecodedSignature {
        kind: "method",
        parse_status: if decoded { "decoded" } else { "partial" },
        calling_convention: Some(calling_convention(first)),
        generic_parameter_count: header.generic_parameter_count,
        parameter_count: Some(header.parameter_count),
        return_type: Some(return_type.value),
        parameter_types: parameters,
        field_type: None,
        issue: if decoded {
            None
        } else {
            Some("Trailing signature data".to_string())
        },
    })
}

/// `methodGenericArity(layout, blob)`.
pub fn method_generic_arity(
    layout: &ManagedMetadataLayout,
    blob: &[u8],
) -> Result<Option<i64>, ManagedReaderFailure> {
    layout
        .budget()
        .admit_transient(blob.len() as i64 * 256, Some(layout.blob.offset as u64))?;
    let mut operands = Vec::new();
    let decoded = decode_signature(blob, &mut operands);
    layout.budget().release_transient();
    Ok(signature_generic_arity(&decoded))
}

/// `signatureGenericArity(decoded)`.
pub fn signature_generic_arity(decoded: &DecodedSignature) -> Option<i64> {
    if decoded.kind == "method" && decoded.parse_status == "decoded" {
        Some(decoded.generic_parameter_count.unwrap_or(0))
    } else {
        None
    }
}

/// `(codedIndex) => Buffer | null`: the 32-byte name digest of a type operand.
pub type SignatureTypeName<'a> = dyn FnMut(i64) -> Option<Vec<u8>> + 'a;

const OPERAND_MARKER: [u8; 1] = [0xff];

fn resolved_sha256(
    blob: &[u8],
    operands: &[TypeOperand],
    type_name: &mut SignatureTypeName<'_>,
) -> Option<String> {
    let mut hasher = Sha256::new();
    let mut copied = 0i64;
    for operand in operands {
        let name = type_name(operand.value)?;
        hasher.update(&blob[copied as usize..operand.offset as usize]);
        hasher.update(OPERAND_MARKER);
        hasher.update(&name);
        copied = operand.next;
    }
    hasher.update(&blob[copied as usize..]);
    Some(format!("{:x}", hasher.finalize()))
}

/// Decode a signature returning both the projection value and the kind/arity
/// needed by callers that build `MemberCore`.
pub fn signature_with_facts(
    blob: &[u8],
    raw_sha256: Option<String>,
    type_name: &mut SignatureTypeName<'_>,
) -> (Value, &'static str, Option<i64>) {
    let mut operands: Vec<TypeOperand> = Vec::new();
    let decoded = decode_signature(blob, &mut operands);
    let kind = decoded.kind;
    let arity = signature_generic_arity(&decoded);
    let raw_sha = raw_sha256.unwrap_or_else(|| sha256_bytes(blob));
    let resolved = if decoded.kind == "unknown" {
        None
    } else {
        resolved_sha256(blob, &operands, type_name)
    };
    let value = decoded_to_value(decoded, blob.len(), raw_sha, resolved);
    (value, kind, arity)
}

fn decoded_to_value(
    decoded: DecodedSignature,
    raw_length: usize,
    raw_sha: String,
    resolved: Option<String>,
) -> Value {
    let mut map = Map::new();
    map.insert("raw_length".into(), Value::from(raw_length));
    map.insert("raw_sha256".into(), Value::from(raw_sha));
    map.insert(
        "resolved_sha256".into(),
        match resolved {
            Some(resolved) => Value::from(resolved),
            None => Value::Null,
        },
    );
    map.insert("kind".into(), Value::from(decoded.kind));
    map.insert("parse_status".into(), Value::from(decoded.parse_status));
    map.insert(
        "calling_convention".into(),
        decoded
            .calling_convention
            .map(Value::from)
            .unwrap_or(Value::Null),
    );
    map.insert(
        "generic_parameter_count".into(),
        decoded
            .generic_parameter_count
            .map(Value::from)
            .unwrap_or(Value::Null),
    );
    map.insert(
        "parameter_count".into(),
        decoded
            .parameter_count
            .map(Value::from)
            .unwrap_or(Value::Null),
    );
    map.insert(
        "return_type".into(),
        decoded.return_type.map(Value::from).unwrap_or(Value::Null),
    );
    map.insert(
        "parameter_types".into(),
        Value::Array(
            decoded
                .parameter_types
                .into_iter()
                .map(Value::from)
                .collect(),
        ),
    );
    map.insert(
        "field_type".into(),
        decoded.field_type.map(Value::from).unwrap_or(Value::Null),
    );
    map.insert(
        "issue".into(),
        decoded.issue.map(Value::from).unwrap_or(Value::Null),
    );
    Value::Object(map)
}
