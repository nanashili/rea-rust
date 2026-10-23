//! CIL opcode table, operand readers, and method data-section parsing.
//!
//! Port of `src/dotnet/ManagedMemberInstructionDecoder.ts`. Decoding reads only
//! the file-backed IL bytes handed to it; the two-byte `0xFE` prefix extends the
//! single-byte table, operand extents are bounded before any value is read, and
//! truncation is reported rather than throwing.

use std::collections::HashMap;

use super::budget::ManagedDecodeBudget;
use super::bytes::{read_f32, read_f64, read_i8, read_i32, read_i64, read_u8, read_u16, read_u32};
use super::failure::{InternalFailure, ManagedReaderFailure};

/// One decoded instruction: IL offset, opcode mnemonic, operand kind and value.
#[derive(Clone)]
pub struct ParsedInstruction {
    pub offset: i64,
    pub opcode: &'static str,
    pub operand_kind: &'static str,
    pub operand: Option<String>,
}

/// One exception-handling clause, in schema field order.
#[derive(Clone)]
pub struct ManagedExceptionRegion {
    pub flags: i64,
    pub try_offset: i64,
    pub try_length: i64,
    pub handler_offset: i64,
    pub handler_length: i64,
    pub class_token: Option<String>,
    pub filter_offset: Option<i64>,
}

impl ManagedExceptionRegion {
    pub fn to_value(&self) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        map.insert("flags".into(), self.flags.into());
        map.insert("try_offset".into(), self.try_offset.into());
        map.insert("try_length".into(), self.try_length.into());
        map.insert("handler_offset".into(), self.handler_offset.into());
        map.insert("handler_length".into(), self.handler_length.into());
        map.insert(
            "class_token".into(),
            match &self.class_token {
                Some(token) => serde_json::Value::from(token.clone()),
                None => serde_json::Value::Null,
            },
        );
        map.insert(
            "filter_offset".into(),
            match self.filter_offset {
                Some(offset) => serde_json::Value::from(offset),
                None => serde_json::Value::Null,
            },
        );
        serde_json::Value::Object(map)
    }
}

fn is_prefix_opcode(name: &str) -> bool {
    matches!(
        name,
        "unaligned." | "volatile." | "tail." | "constrained." | "readonly." | "no."
    )
}

struct Opcode {
    name: &'static str,
    operand: &'static str,
}

/// Single-byte and `0xFE`-prefixed opcode table keyed by the ECMA-335 numeric
/// code (`0xFExx` for the prefixed group).
fn opcode(code: u32) -> Option<Opcode> {
    let entry: Option<(&'static str, &'static str)> = match code {
        0x00 => Some(("nop", "none")),
        0x01 => Some(("break", "none")),
        0x02 => Some(("ldarg.0", "none")),
        0x03 => Some(("ldarg.1", "none")),
        0x04 => Some(("ldarg.2", "none")),
        0x05 => Some(("ldarg.3", "none")),
        0x06 => Some(("ldloc.0", "none")),
        0x07 => Some(("ldloc.1", "none")),
        0x08 => Some(("ldloc.2", "none")),
        0x09 => Some(("ldloc.3", "none")),
        0x0a => Some(("stloc.0", "none")),
        0x0b => Some(("stloc.1", "none")),
        0x0c => Some(("stloc.2", "none")),
        0x0d => Some(("stloc.3", "none")),
        0x0e => Some(("ldarg.s", "short-var")),
        0x0f => Some(("ldarga.s", "short-var")),
        0x10 => Some(("starg.s", "short-var")),
        0x11 => Some(("ldloc.s", "short-var")),
        0x12 => Some(("ldloca.s", "short-var")),
        0x13 => Some(("stloc.s", "short-var")),
        0x14 => Some(("ldnull", "none")),
        0x15 => Some(("ldc.i4.m1", "none")),
        0x16 => Some(("ldc.i4.0", "none")),
        0x17 => Some(("ldc.i4.1", "none")),
        0x18 => Some(("ldc.i4.2", "none")),
        0x19 => Some(("ldc.i4.3", "none")),
        0x1a => Some(("ldc.i4.4", "none")),
        0x1b => Some(("ldc.i4.5", "none")),
        0x1c => Some(("ldc.i4.6", "none")),
        0x1d => Some(("ldc.i4.7", "none")),
        0x1e => Some(("ldc.i4.8", "none")),
        0x1f => Some(("ldc.i4.s", "short-i")),
        0x20 => Some(("ldc.i4", "i")),
        0x21 => Some(("ldc.i8", "i8")),
        0x22 => Some(("ldc.r4", "r4")),
        0x23 => Some(("ldc.r8", "r8")),
        0x25 => Some(("dup", "none")),
        0x26 => Some(("pop", "none")),
        0x27 => Some(("jmp", "method")),
        0x28 => Some(("call", "method")),
        0x29 => Some(("calli", "signature")),
        0x2a => Some(("ret", "none")),
        0x2b => Some(("br.s", "short-branch")),
        0x2c => Some(("brfalse.s", "short-branch")),
        0x2d => Some(("brtrue.s", "short-branch")),
        0x2e => Some(("beq.s", "short-branch")),
        0x2f => Some(("bge.s", "short-branch")),
        0x30 => Some(("bgt.s", "short-branch")),
        0x31 => Some(("ble.s", "short-branch")),
        0x32 => Some(("blt.s", "short-branch")),
        0x33 => Some(("bne.un.s", "short-branch")),
        0x34 => Some(("bge.un.s", "short-branch")),
        0x35 => Some(("bgt.un.s", "short-branch")),
        0x36 => Some(("ble.un.s", "short-branch")),
        0x37 => Some(("blt.un.s", "short-branch")),
        0x38 => Some(("br", "branch")),
        0x39 => Some(("brfalse", "branch")),
        0x3a => Some(("brtrue", "branch")),
        0x3b => Some(("beq", "branch")),
        0x3c => Some(("bge", "branch")),
        0x3d => Some(("bgt", "branch")),
        0x3e => Some(("ble", "branch")),
        0x3f => Some(("blt", "branch")),
        0x40 => Some(("bne.un", "branch")),
        0x41 => Some(("bge.un", "branch")),
        0x42 => Some(("bgt.un", "branch")),
        0x43 => Some(("ble.un", "branch")),
        0x44 => Some(("blt.un", "branch")),
        0x45 => Some(("switch", "switch")),
        0x46 => Some(("ldind.i1", "none")),
        0x47 => Some(("ldind.u1", "none")),
        0x48 => Some(("ldind.i2", "none")),
        0x49 => Some(("ldind.u2", "none")),
        0x4a => Some(("ldind.i4", "none")),
        0x4b => Some(("ldind.u4", "none")),
        0x4c => Some(("ldind.i8", "none")),
        0x4d => Some(("ldind.i", "none")),
        0x4e => Some(("ldind.r4", "none")),
        0x4f => Some(("ldind.r8", "none")),
        0x50 => Some(("ldind.ref", "none")),
        0x51 => Some(("stind.ref", "none")),
        0x52 => Some(("stind.i1", "none")),
        0x53 => Some(("stind.i2", "none")),
        0x54 => Some(("stind.i4", "none")),
        0x55 => Some(("stind.i8", "none")),
        0x56 => Some(("stind.r4", "none")),
        0x57 => Some(("stind.r8", "none")),
        0x58 => Some(("add", "none")),
        0x59 => Some(("sub", "none")),
        0x5a => Some(("mul", "none")),
        0x5b => Some(("div", "none")),
        0x5c => Some(("div.un", "none")),
        0x5d => Some(("rem", "none")),
        0x5e => Some(("rem.un", "none")),
        0x5f => Some(("and", "none")),
        0x60 => Some(("or", "none")),
        0x61 => Some(("xor", "none")),
        0x62 => Some(("shl", "none")),
        0x63 => Some(("shr", "none")),
        0x64 => Some(("shr.un", "none")),
        0x65 => Some(("neg", "none")),
        0x66 => Some(("not", "none")),
        0x67 => Some(("conv.i1", "none")),
        0x68 => Some(("conv.i2", "none")),
        0x69 => Some(("conv.i4", "none")),
        0x6a => Some(("conv.i8", "none")),
        0x6b => Some(("conv.r4", "none")),
        0x6c => Some(("conv.r8", "none")),
        0x6d => Some(("conv.u4", "none")),
        0x6e => Some(("conv.u8", "none")),
        0x6f => Some(("callvirt", "method")),
        0x70 => Some(("cpobj", "type")),
        0x71 => Some(("ldobj", "type")),
        0x72 => Some(("ldstr", "string")),
        0x73 => Some(("newobj", "method")),
        0x74 => Some(("castclass", "type")),
        0x75 => Some(("isinst", "type")),
        0x76 => Some(("conv.r.un", "none")),
        0x79 => Some(("unbox", "type")),
        0x7a => Some(("throw", "none")),
        0x7b => Some(("ldfld", "field")),
        0x7c => Some(("ldflda", "field")),
        0x7d => Some(("stfld", "field")),
        0x7e => Some(("ldsfld", "field")),
        0x7f => Some(("ldsflda", "field")),
        0x80 => Some(("stsfld", "field")),
        0x81 => Some(("stobj", "type")),
        0x82 => Some(("conv.ovf.i1.un", "none")),
        0x83 => Some(("conv.ovf.i2.un", "none")),
        0x84 => Some(("conv.ovf.i4.un", "none")),
        0x85 => Some(("conv.ovf.i8.un", "none")),
        0x86 => Some(("conv.ovf.u1.un", "none")),
        0x87 => Some(("conv.ovf.u2.un", "none")),
        0x88 => Some(("conv.ovf.u4.un", "none")),
        0x89 => Some(("conv.ovf.u8.un", "none")),
        0x8a => Some(("conv.ovf.i.un", "none")),
        0x8b => Some(("conv.ovf.u.un", "none")),
        0x8c => Some(("box", "type")),
        0x8d => Some(("newarr", "type")),
        0x8e => Some(("ldlen", "none")),
        0x8f => Some(("ldelema", "type")),
        0x90 => Some(("ldelem.i1", "none")),
        0x91 => Some(("ldelem.u1", "none")),
        0x92 => Some(("ldelem.i2", "none")),
        0x93 => Some(("ldelem.u2", "none")),
        0x94 => Some(("ldelem.i4", "none")),
        0x95 => Some(("ldelem.u4", "none")),
        0x96 => Some(("ldelem.i8", "none")),
        0x97 => Some(("ldelem.i", "none")),
        0x98 => Some(("ldelem.r4", "none")),
        0x99 => Some(("ldelem.r8", "none")),
        0x9a => Some(("ldelem.ref", "none")),
        0x9b => Some(("stelem.i", "none")),
        0x9c => Some(("stelem.i1", "none")),
        0x9d => Some(("stelem.i2", "none")),
        0x9e => Some(("stelem.i4", "none")),
        0x9f => Some(("stelem.i8", "none")),
        0xa0 => Some(("stelem.r4", "none")),
        0xa1 => Some(("stelem.r8", "none")),
        0xa2 => Some(("stelem.ref", "none")),
        0xa3 => Some(("ldelem", "type")),
        0xa4 => Some(("stelem", "type")),
        0xa5 => Some(("unbox.any", "type")),
        0xb3 => Some(("conv.ovf.i1", "none")),
        0xb4 => Some(("conv.ovf.u1", "none")),
        0xb5 => Some(("conv.ovf.i2", "none")),
        0xb6 => Some(("conv.ovf.u2", "none")),
        0xb7 => Some(("conv.ovf.i4", "none")),
        0xb8 => Some(("conv.ovf.u4", "none")),
        0xb9 => Some(("conv.ovf.i8", "none")),
        0xba => Some(("conv.ovf.u8", "none")),
        0xc2 => Some(("refanyval", "type")),
        0xc3 => Some(("ckfinite", "none")),
        0xc6 => Some(("mkrefany", "type")),
        0xd0 => Some(("ldtoken", "token")),
        0xd1 => Some(("conv.u2", "none")),
        0xd2 => Some(("conv.u1", "none")),
        0xd3 => Some(("conv.i", "none")),
        0xd4 => Some(("conv.ovf.i", "none")),
        0xd5 => Some(("conv.ovf.u", "none")),
        0xd6 => Some(("add.ovf", "none")),
        0xd7 => Some(("add.ovf.un", "none")),
        0xd8 => Some(("mul.ovf", "none")),
        0xd9 => Some(("mul.ovf.un", "none")),
        0xda => Some(("sub.ovf", "none")),
        0xdb => Some(("sub.ovf.un", "none")),
        0xdc => Some(("endfinally", "none")),
        0xdd => Some(("leave", "branch")),
        0xde => Some(("leave.s", "short-branch")),
        0xdf => Some(("stind.i", "none")),
        0xe0 => Some(("conv.u", "none")),
        0xfe00 => Some(("arglist", "none")),
        0xfe01 => Some(("ceq", "none")),
        0xfe02 => Some(("cgt", "none")),
        0xfe03 => Some(("cgt.un", "none")),
        0xfe04 => Some(("clt", "none")),
        0xfe05 => Some(("clt.un", "none")),
        0xfe06 => Some(("ldftn", "method")),
        0xfe07 => Some(("ldvirtftn", "method")),
        0xfe09 => Some(("ldarg", "var")),
        0xfe0a => Some(("ldarga", "var")),
        0xfe0b => Some(("starg", "var")),
        0xfe0c => Some(("ldloc", "var")),
        0xfe0d => Some(("ldloca", "var")),
        0xfe0e => Some(("stloc", "var")),
        0xfe0f => Some(("localloc", "none")),
        0xfe11 => Some(("endfilter", "none")),
        0xfe12 => Some(("unaligned.", "short-i")),
        0xfe13 => Some(("volatile.", "none")),
        0xfe14 => Some(("tail.", "none")),
        0xfe15 => Some(("initobj", "type")),
        0xfe16 => Some(("constrained.", "type")),
        0xfe17 => Some(("cpblk", "none")),
        0xfe18 => Some(("initblk", "none")),
        0xfe19 => Some(("no.", "short-i")),
        0xfe1a => Some(("rethrow", "none")),
        0xfe1c => Some(("sizeof", "type")),
        0xfe1d => Some(("refanytype", "none")),
        0xfe1e => Some(("readonly.", "none")),
        _ => None,
    };
    entry.map(|(name, operand)| Opcode { name, operand })
}

fn token_kind(token: &str) -> &'static str {
    if token.starts_with("0x06") || token.starts_with("0x0a") || token.starts_with("0x2b") {
        "method"
    } else if token.starts_with("0x04") {
        "field"
    } else if token.starts_with("0x70") {
        "string"
    } else if token.starts_with("0x11") {
        "signature"
    } else if token.starts_with("0x01") || token.starts_with("0x02") || token.starts_with("0x1b") {
        "type"
    } else {
        "token"
    }
}

struct OperandResult {
    next: i64,
    anchor_kind: &'static str,
    value: Option<String>,
}

/// `String(-0)` loses a CIL constant's sign; keep it in anchors and hashes.
fn floating_point_operand_f32(value: f32) -> String {
    if value == 0.0 && value.is_sign_negative() {
        "-0".to_string()
    } else {
        js_number_f64(value as f64)
    }
}

fn floating_point_operand_f64(value: f64) -> String {
    if value == 0.0 && value.is_sign_negative() {
        "-0".to_string()
    } else {
        js_number_f64(value)
    }
}

/// `String(number)` for an `f64`, matching ECMAScript number-to-string for the
/// finite and non-finite values a CIL constant can hold.
fn js_number_f64(value: f64) -> String {
    if value.is_nan() {
        return "NaN".to_string();
    }
    if value.is_infinite() {
        return if value > 0.0 { "Infinity" } else { "-Infinity" }.to_string();
    }
    if value == value.trunc() && value.abs() < 1e21 {
        let as_i = value as i64;
        if as_i as f64 == value {
            return as_i.to_string();
        }
    }
    let mut text = format!("{value}");
    if text.contains('e') {
        text = text.replace('e', "e+").replace("e+-", "e-");
    }
    text
}

const TOKEN_OPERAND_WIDTH: i64 = 4;

/// Bytes an operand of `kind` occupies at `offset`, or `None` when the extent
/// itself cannot be read (a truncated switch count).
fn operand_extent(il: &[u8], offset: i64, kind: &str) -> Result<Option<i64>, InternalFailure> {
    if let Some(width) = fixed_width(kind) {
        return Ok(Some(width));
    }
    if kind == "switch" {
        if offset > il.len() as i64 - 4 {
            return Ok(None);
        }
        let count = read_u32(il, offset as usize)? as i64;
        return Ok(Some(4 + count * 4));
    }
    if is_token_kind(kind) || kind == "token" {
        Ok(Some(TOKEN_OPERAND_WIDTH))
    } else {
        Ok(Some(0))
    }
}

fn fixed_width(kind: &str) -> Option<i64> {
    match kind {
        "none" => Some(0),
        "short-var" => Some(1),
        "var" => Some(2),
        "short-i" => Some(1),
        "i" => Some(4),
        "i8" => Some(8),
        "r4" => Some(4),
        "r8" => Some(8),
        "short-branch" => Some(1),
        "branch" => Some(4),
        _ => None,
    }
}

fn is_token_kind(kind: &str) -> bool {
    matches!(kind, "method" | "field" | "type" | "string" | "signature")
}

fn token_operand_kind(kind: &str) -> Option<&'static str> {
    match kind {
        "method" => Some("method"),
        "field" => Some("field"),
        "type" => Some("type"),
        "string" => Some("string"),
        "signature" => Some("signature"),
        _ => None,
    }
}

/// Read an operand whose extent is already known to fit.
fn read_operand(il: &[u8], offset: i64, kind: &str) -> Result<OperandResult, InternalFailure> {
    let at = offset as usize;
    match kind {
        "none" => Ok(OperandResult {
            next: offset,
            anchor_kind: "none",
            value: None,
        }),
        "short-var" => Ok(OperandResult {
            next: offset + 1,
            anchor_kind: "variable",
            value: Some((read_u8(il, at)? as i64).to_string()),
        }),
        "var" => Ok(OperandResult {
            next: offset + 2,
            anchor_kind: "variable",
            value: Some((read_u16(il, at)? as i64).to_string()),
        }),
        "short-i" => Ok(OperandResult {
            next: offset + 1,
            anchor_kind: "constant",
            value: Some((read_i8(il, at)? as i64).to_string()),
        }),
        "i" => Ok(OperandResult {
            next: offset + 4,
            anchor_kind: "constant",
            value: Some((read_i32(il, at)? as i64).to_string()),
        }),
        "i8" => Ok(OperandResult {
            next: offset + 8,
            anchor_kind: "constant",
            value: Some(read_i64(il, at)?.to_string()),
        }),
        "r4" => Ok(OperandResult {
            next: offset + 4,
            anchor_kind: "constant",
            value: Some(floating_point_operand_f32(read_f32(il, at)?)),
        }),
        "r8" => Ok(OperandResult {
            next: offset + 8,
            anchor_kind: "constant",
            value: Some(floating_point_operand_f64(read_f64(il, at)?)),
        }),
        "short-branch" => Ok(OperandResult {
            next: offset + 1,
            anchor_kind: "branch",
            value: Some((offset + 1 + read_i8(il, at)? as i64).to_string()),
        }),
        "branch" => Ok(OperandResult {
            next: offset + 4,
            anchor_kind: "branch",
            value: Some((offset + 4 + read_i32(il, at)? as i64).to_string()),
        }),
        "switch" => {
            let count = read_u32(il, at)? as i64;
            Ok(OperandResult {
                next: offset + 4 + count * 4,
                anchor_kind: "switch",
                value: Some(count.to_string()),
            })
        }
        other => {
            if !is_token_kind(other) && other != "token" {
                return Ok(OperandResult {
                    next: offset,
                    anchor_kind: "unknown",
                    value: None,
                });
            }
            let raw = read_u32(il, at)?;
            let token = format!("0x{raw:08x}");
            let anchor_kind = token_operand_kind(other).unwrap_or_else(|| token_kind(&token));
            Ok(OperandResult {
                next: offset + TOKEN_OPERAND_WIDTH,
                anchor_kind,
                value: Some(token),
            })
        }
    }
}

/// Result of decoding a complete method's CIL stream.
pub struct DecodedInstructions {
    pub parsed: Vec<ParsedInstruction>,
    pub instruction_starts: Vec<i64>,
    pub count: i64,
    pub truncated: i64,
    pub issue: Option<String>,
}

/// `decodeInstructions(il, admitInstruction)`.
///
/// `admit_instruction` charges one retained instruction record before the
/// decoded arrays grow; it may propagate a `resource-limit` failure as a
/// [`ManagedReaderFailure`] which the caller rethrows.
pub fn decode_instructions(
    il: &[u8],
    mut admit_instruction: Option<&mut dyn FnMut(i64) -> Result<(), ManagedReaderFailure>>,
) -> Result<DecodedInstructions, ManagedReaderFailure> {
    let mut parsed: Vec<ParsedInstruction> = Vec::new();
    let mut instruction_starts: Vec<i64> = Vec::new();
    let mut offset: i64 = 0;
    let mut prefix_start: Option<i64> = None;
    let mut issue: Option<String> = None;
    let len = il.len() as i64;

    while offset < len {
        let start = offset;
        let first = match read_u8(il, offset as usize) {
            Ok(value) => value,
            Err(internal) => {
                issue = Some(internal.0);
                break;
            }
        };
        offset += 1;
        if first == 0xfe && offset >= len {
            issue = Some(format!(
                "Two-byte CIL opcode at IL offset {start} leaves method body"
            ));
            break;
        }
        let code = if first == 0xfe {
            let second = match read_u8(il, offset as usize) {
                Ok(value) => value,
                Err(internal) => {
                    issue = Some(internal.0);
                    break;
                }
            };
            offset += 1;
            0xfe00 + second as u32
        } else {
            first as u32
        };
        let descriptor = match opcode(code) {
            Some(descriptor) => descriptor,
            None => {
                issue = Some(format!(
                    "Unsupported CIL opcode 0x{code:x} at IL offset {start}"
                ));
                break;
            }
        };
        let extent = match operand_extent(il, offset, descriptor.operand) {
            Ok(extent) => extent,
            Err(internal) => {
                issue = Some(internal.0);
                break;
            }
        };
        let extent = match extent {
            Some(extent) if offset + extent <= len => extent,
            _ => {
                issue = Some(format!(
                    "Instruction {} at IL offset {start} leaves method body",
                    descriptor.name
                ));
                break;
            }
        };
        let _ = extent;
        let operand = match read_operand(il, offset, descriptor.operand) {
            Ok(operand) => operand,
            Err(internal) => {
                issue = Some(internal.0);
                break;
            }
        };
        if let Some(admit) = admit_instruction.as_deref_mut() {
            admit(start)?;
        }
        offset = operand.next;
        if is_prefix_opcode(descriptor.name) {
            prefix_start.get_or_insert(start);
        } else {
            instruction_starts.push(prefix_start.take().unwrap_or(start));
        }
        parsed.push(ParsedInstruction {
            offset: start,
            opcode: descriptor.name,
            operand_kind: operand.anchor_kind,
            operand: operand.value,
        });
    }

    let truncated = if offset < len && issue.is_none() {
        1
    } else {
        0
    };
    let count = parsed.len() as i64;
    Ok(DecodedInstructions {
        parsed,
        instruction_starts,
        count,
        truncated,
        issue,
    })
}

/// `[opcode, operand_kind, operand]` tuples serialized exactly as
/// `JSON.stringify` would, for the normalized-IL digest.
pub fn normalized_tuples_json(parsed: &[ParsedInstruction]) -> Vec<u8> {
    let array = serde_json::Value::Array(
        parsed
            .iter()
            .map(|instruction| {
                serde_json::Value::Array(vec![
                    serde_json::Value::from(instruction.opcode),
                    serde_json::Value::from(instruction.operand_kind),
                    match &instruction.operand {
                        Some(operand) => serde_json::Value::from(operand.clone()),
                        None => serde_json::Value::Null,
                    },
                ])
            })
            .collect(),
    );
    serde_json::to_vec(&array).unwrap_or_default()
}

/// Opcode occurrence counts in first-seen insertion order, like the TS
/// `Record` built by incrementing per opcode.
pub fn opcode_counts(parsed: &[ParsedInstruction]) -> serde_json::Map<String, serde_json::Value> {
    let mut counts: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
    let mut seen: HashMap<&str, i64> = HashMap::new();
    for instruction in parsed {
        let entry = seen.entry(instruction.opcode).or_insert(0);
        *entry += 1;
        counts.insert(
            instruction.opcode.to_string(),
            serde_json::Value::from(*entry),
        );
    }
    counts
}

/// The result of parsing a method's data sections.
pub enum ExceptionRegionParseResult {
    Complete {
        regions: Vec<ManagedExceptionRegion>,
    },
    Malformed {
        regions: Vec<ManagedExceptionRegion>,
        issue: String,
    },
}

impl ExceptionRegionParseResult {
    pub fn regions(&self) -> &[ManagedExceptionRegion] {
        match self {
            ExceptionRegionParseResult::Complete { regions } => regions,
            ExceptionRegionParseResult::Malformed { regions, .. } => regions,
        }
    }
    pub fn issue(&self) -> Option<&str> {
        match self {
            ExceptionRegionParseResult::Malformed { issue, .. } => Some(issue),
            ExceptionRegionParseResult::Complete { .. } => None,
        }
    }
}

fn malformed_regions(
    issue: &str,
    regions: Vec<ManagedExceptionRegion>,
) -> ExceptionRegionParseResult {
    ExceptionRegionParseResult::Malformed {
        regions,
        issue: issue.to_string(),
    }
}

/// `parseExceptionRegions(bytes, offset, methodEnd, budget)`.
pub fn parse_exception_regions(
    bytes: &[u8],
    offset: i64,
    method_end: i64,
    mut budget: Option<&mut ManagedDecodeBudget>,
) -> Result<ExceptionRegionParseResult, ManagedReaderFailure> {
    let mut regions: Vec<ManagedExceptionRegion> = Vec::new();
    let mut section_offset = offset;
    let mut has_more_sections = true;
    let buffer_len = bytes.len() as i64;
    while has_more_sections {
        if section_offset < 0 || section_offset > method_end - 4 || section_offset > buffer_len - 4
        {
            return Ok(malformed_regions(
                "Exception section header leaves artifact",
                regions,
            ));
        }
        let kind = byte_at(bytes, section_offset);
        if (kind & 0x3f) != 1 {
            return Ok(malformed_regions(
                &format!("Unsupported method data section kind {}", kind & 0x3f),
                regions,
            ));
        }
        let fat = (kind & 0x40) != 0;
        let size: i64 = if fat {
            byte_at(bytes, section_offset + 1) as i64
                | ((byte_at(bytes, section_offset + 2) as i64) << 8)
                | ((byte_at(bytes, section_offset + 3) as i64) << 16)
        } else {
            byte_at(bytes, section_offset + 1) as i64
        };
        let clause_size: i64 = if fat { 24 } else { 12 };
        if size < 4 || section_offset > method_end - size || section_offset > buffer_len - size {
            return Ok(malformed_regions(
                "Exception section size leaves artifact",
                regions,
            ));
        }
        let count: i64;
        let mut section_size = size;
        if fat {
            if (size - 4) % clause_size != 0 {
                return Ok(malformed_regions(
                    "Exception section size does not contain whole clauses",
                    regions,
                ));
            }
            count = (size - 4) / clause_size;
        } else if (size - 4) % clause_size == 0 {
            count = (size - 4) / clause_size;
        } else if size >= clause_size && size % clause_size == 0 {
            count = size / clause_size;
            section_size = 4 + count * clause_size;
        } else {
            return Ok(malformed_regions(
                "Exception section size does not contain whole clauses",
                regions,
            ));
        }
        if section_offset > method_end - section_size || section_offset > buffer_len - section_size
        {
            return Ok(malformed_regions(
                "Exception section size leaves artifact",
                regions,
            ));
        }
        if !fat
            && (byte_at(bytes, section_offset + 2) != 0 || byte_at(bytes, section_offset + 3) != 0)
        {
            return Ok(malformed_regions(
                "Small exception section reserved bytes are nonzero",
                regions,
            ));
        }
        if let Some(budget) = budget.as_deref_mut() {
            budget.admit_transient(count * 256, Some(section_offset as u64))?;
        }
        for region in read_exception_clauses(bytes, section_offset + 4, count, fat) {
            regions.push(region);
        }
        has_more_sections = (kind & 0x80) != 0;
        section_offset += section_size;
    }
    Ok(ExceptionRegionParseResult::Complete { regions })
}

fn byte_at(bytes: &[u8], offset: i64) -> u8 {
    if offset < 0 {
        0
    } else {
        bytes.get(offset as usize).copied().unwrap_or(0)
    }
}

fn read_exception_clauses(
    bytes: &[u8],
    start: i64,
    count: i64,
    fat: bool,
) -> Vec<ManagedExceptionRegion> {
    let mut regions: Vec<ManagedExceptionRegion> = Vec::new();
    let clause_size: i64 = if fat { 24 } else { 12 };
    for index in 0..count {
        let clause = start + index * clause_size;
        let flags: i64 = if fat {
            u32_at(bytes, clause) as i64
        } else {
            u16_at(bytes, clause) as i64
        };
        let extra = u32_at(bytes, clause + if fat { 20 } else { 8 });
        regions.push(ManagedExceptionRegion {
            flags,
            try_offset: if fat {
                u32_at(bytes, clause + 4) as i64
            } else {
                u16_at(bytes, clause + 2) as i64
            },
            try_length: if fat {
                u32_at(bytes, clause + 8) as i64
            } else {
                byte_at(bytes, clause + 4) as i64
            },
            handler_offset: if fat {
                u32_at(bytes, clause + 12) as i64
            } else {
                u16_at(bytes, clause + 5) as i64
            },
            handler_length: if fat {
                u32_at(bytes, clause + 16) as i64
            } else {
                byte_at(bytes, clause + 7) as i64
            },
            class_token: if flags == 0 {
                Some(format!("0x{extra:08x}"))
            } else {
                None
            },
            filter_offset: if flags == 1 { Some(extra as i64) } else { None },
        });
    }
    regions
}

fn u16_at(bytes: &[u8], offset: i64) -> u16 {
    read_u16(bytes, offset.max(0) as usize).unwrap_or(0)
}

fn u32_at(bytes: &[u8], offset: i64) -> u32 {
    read_u32(bytes, offset.max(0) as usize).unwrap_or(0)
}
