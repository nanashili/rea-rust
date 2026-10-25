//! MethodSpec edge targets and generic-arity validation.
//!
//! Port of `src/dotnet/ManagedMethodSpecs.ts`. Fields, member references, and
//! methods are indexed by token, then each MethodSpec an inspected body calls
//! is named after the generic method it instantiates, so every edge target
//! resolves through one lookup.

use std::collections::{HashMap, HashSet};

use super::failure::{
    ManagedParseIssue, ReadError, ReadResult, managed_failure, read_managed_value,
};
use super::heaps::{
    metadata_coded_token, metadata_coded_token_invalid_reason, metadata_row_cursor,
    read_metadata_blob,
};
use super::layout::ManagedMetadataLayout;
use super::member_core::{MemberCore, method_generic_arity, spec_signature};
use super::method_body::Anchor;

/// Output of `edgeTargets`: the member index by token and the issues observed.
pub struct EdgeTargets {
    pub members: HashMap<String, MemberCore>,
    pub issues: Vec<ManagedParseIssue>,
}

/// `edgeTargets(bytes, layout, methods, cores)`.
pub fn edge_targets(
    bytes: &[u8],
    layout: &ManagedMetadataLayout,
    method_anchors: &[Vec<Anchor>],
    cores: &[HashMap<String, MemberCore>],
) -> ReadResult<EdgeTargets> {
    let mut members: HashMap<String, MemberCore> = HashMap::new();
    for core in cores {
        for (token, member) in core {
            members.insert(token.clone(), member.clone());
        }
    }
    let mut issues: Vec<ManagedParseIssue> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    // Generic arity by method token, so instantiations of one method decode it once.
    let mut arities: HashMap<String, Option<i64>> = HashMap::new();
    for anchors in method_anchors {
        for anchor in anchors {
            let operand = match &anchor.operand {
                Some(operand) if operand.starts_with("0x2b") => operand.clone(),
                _ => continue,
            };
            if seen.contains(&operand) {
                continue;
            }
            seen.insert(operand.clone());
            // Issues the read records come before the failure it may throw.
            let mut recorded = Vec::new();
            let outcome = read_method_spec(
                bytes,
                layout,
                &mut members,
                &mut recorded,
                &mut arities,
                &operand,
            );
            issues.append(&mut recorded);
            read_managed_value(|| outcome, &mut issues)?;
        }
    }
    Ok(EdgeTargets { members, issues })
}

/// Map one MethodSpec to its generic method, then check its instantiation
/// decodes and matches that method's generic arity.
fn read_method_spec(
    bytes: &[u8],
    layout: &ManagedMetadataLayout,
    members: &mut HashMap<String, MemberCore>,
    issues: &mut Vec<ManagedParseIssue>,
    arities: &mut HashMap<String, Option<i64>>,
    token: &str,
) -> ReadResult<()> {
    let scope = format!("metadata.MethodSpec:{token}");
    let row = i64::from_str_radix(&token[4..], 16).unwrap_or(0);
    let mut cursor = metadata_row_cursor(bytes, layout, 0x2b, row)?;
    let method_raw = cursor.read_index(layout.coded_index_size("MethodDefOrRef"))?;
    let instantiation = cursor.read_index(layout.blob_index_size)?;
    let method_reason = metadata_coded_token_invalid_reason(
        method_raw,
        1,
        &[Some(6), Some(10)],
        &layout.row_counts,
    );
    if method_reason.is_some() || method_raw == 0 {
        issues.push(ManagedParseIssue {
            code: "invalid-row",
            scope: scope.clone(),
            offset: Some(cursor.start as u64),
            detail: match &method_reason {
                None => "MethodSpec method coded index 0x0 is null, but the Method column must reference a row".to_string(),
                Some(reason) => format!(
                    "MethodSpec method coded index 0x{:x} is invalid: {reason}",
                    method_raw
                ),
            },
        });
    }
    let generic = metadata_coded_token(method_raw, 1, &[Some(6), Some(10)], &layout.row_counts);
    let target = generic
        .as_ref()
        .and_then(|generic| members.get(generic).cloned());
    // A MethodSpec instantiates a method, so a field target never lends it a name.
    if let Some(target) = &target {
        if target.kind != "field" {
            let mut copy = target.clone();
            copy.token = token.to_string();
            members.insert(token.to_string(), copy);
        }
    }
    let spec = read_metadata_blob(bytes, layout, instantiation, layout.blob.size)?.to_vec();
    let types = spec_signature(layout, &spec, "instantiation", &scope, cursor.start)?;
    let generic = match generic {
        Some(generic) => generic,
        None => return Ok(()),
    };
    // Prefer the arity the target's owner decoded; read the raw signature only
    // for a target nothing decoded.
    let target_arity = target.as_ref().and_then(|target| target.generic_arity);
    if target_arity.is_none() && !arities.contains_key(&generic) {
        let signature_blob = method_signature_blob(bytes, layout, &generic)?;
        let arity = method_generic_arity(layout, &signature_blob)?;
        arities.insert(generic.clone(), arity);
    }
    let arity = match target_arity {
        Some(arity) => arity,
        None => arities.get(&generic).copied().flatten(),
    };
    // A missing arity never matches an argument count, including zero.
    if arity != Some(types.len() as i64) {
        return Err(ReadError::Reader(managed_failure(
            "invalid-row",
            scope,
            match arity {
                None => "MethodSpec method does not have a decodable method signature".to_string(),
                Some(arity) => format!(
                    "MethodSpec supplies {} type argument(s), but its method declares {} generic parameter(s)",
                    types.len(),
                    arity
                ),
            },
            Some(cursor.start as u64),
        )));
    }
    Ok(())
}

/// The Signature column of a MethodDef or MemberRef row.
fn method_signature_blob(
    bytes: &[u8],
    layout: &ManagedMetadataLayout,
    token: &str,
) -> ReadResult<Vec<u8>> {
    let table = usize::from_str_radix(&token[2..4], 16).unwrap_or(0);
    let row = i64::from_str_radix(&token[4..], 16).unwrap_or(0);
    let mut cursor = metadata_row_cursor(bytes, layout, table, row)?;
    if table == 6 {
        cursor.read_u32()?;
        cursor.read_u16()?;
        cursor.read_u16()?;
    } else {
        cursor.read_index(layout.coded_index_size("MemberRefParent"))?;
    }
    cursor.read_index(layout.string_index_size)?;
    let blob = read_metadata_blob(
        bytes,
        layout,
        cursor.read_index(layout.blob_index_size)?,
        layout.blob.size,
    )?
    .to_vec();
    Ok(blob)
}
