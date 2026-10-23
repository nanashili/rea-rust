//! Nominal type-name digests for signature operands and TypeDef rows.
//!
//! Port of `src/dotnet/ManagedTypeNameDigests.ts`. Each type operand is named
//! independently of its metadata rows: a TypeDef or TypeRef by its
//! namespace-qualified name, framed after its enclosing types for a nested
//! type (`Outer/Inner`). A TypeSpec, an unreadable row, cyclic nesting, or
//! nesting deeper than the cap has no digest. The public entry builds a
//! `SignatureTypeName` closure keyed by coded index.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use sha2::{Digest, Sha256};

use super::failure::{
    ManagedParseIssue, ReadError, ReadResult, managed_failure, read_managed_value,
};
use super::heaps::metadata_token;
use super::layout::ManagedMetadataLayout;
use super::member_core::ParsedType;
use super::type_nesting::ManagedTypeNesting;
use super::type_references::ManagedTypeReferences;

const TYPE_DEF: usize = 2;

/// Deepest type nesting REA names, counting the outermost type as 1.
pub const MAX_TYPE_NESTING_DEPTH: usize = 64;

/// Digest prefixes that keep a top-level type apart from a nested one.
const TOP_LEVEL: [u8; 1] = [0];
const NESTED: [u8; 1] = [1];
/// Separates a namespace from a name; #Strings entries hold no NUL.
const NAME_SEPARATOR: [u8; 1] = [0];

/// One type's own namespace and name, and its enclosing type's row if nested.
struct TypeLink {
    namespace: String,
    name: String,
    enclosing_row: Option<i64>,
}

#[derive(Clone)]
struct NamedRow {
    digest: Vec<u8>,
    depth: usize,
}

/// Memoized nested-type digest walk over a `link` callback.
///
/// Mirrors `nestedTypeDigests`: each row is read and digested once, so naming a
/// chain is linear in its length; a gap, a cycle, or nesting deeper than
/// `MAX_TYPE_NESTING_DEPTH` has no digest. `retain` is charged once per row read
/// and once per remembered row.
struct NestedTypeDigests {
    named: HashMap<i64, Option<NamedRow>>,
    links: HashMap<i64, Option<TypeLink>>,
}

impl NestedTypeDigests {
    fn new() -> Self {
        Self {
            named: HashMap::new(),
            links: HashMap::new(),
        }
    }

    fn remember(
        &mut self,
        retain: &mut dyn FnMut() -> ReadResult<()>,
        row: i64,
        value: Option<NamedRow>,
    ) -> ReadResult<()> {
        retain()?;
        self.named.insert(row, value);
        Ok(())
    }

    fn read_link(
        &mut self,
        link: &mut dyn FnMut(i64) -> ReadResult<Option<TypeLink>>,
        retain: &mut dyn FnMut() -> ReadResult<()>,
        row: i64,
    ) -> ReadResult<Option<&TypeLink>> {
        if !self.links.contains_key(&row) {
            let read = link(row)?;
            retain()?;
            self.links.insert(row, read);
        }
        Ok(self.links.get(&row).and_then(|value| value.as_ref()))
    }

    /// `(row) => Buffer | null`.
    fn digest(
        &mut self,
        link: &mut dyn FnMut(i64) -> ReadResult<Option<TypeLink>>,
        retain: &mut dyn FnMut() -> ReadResult<()>,
        row: i64,
    ) -> ReadResult<Option<Vec<u8>>> {
        struct Step {
            row: i64,
            namespace: String,
            name: String,
        }
        // Walk out to a named row or the outermost type, at most past the cap.
        let mut path: Vec<Step> = Vec::new();
        let mut seen: std::collections::HashSet<i64> = std::collections::HashSet::new();
        let mut outer: Option<NamedRow> = None;
        let mut current: Option<i64> = Some(row);
        loop {
            let current_row = match current {
                Some(value) => value,
                None => break,
            };
            if let Some(known) = self.named.get(&current_row) {
                match known.clone() {
                    None => {
                        for step in &path {
                            self.remember(retain, step.row, None)?;
                        }
                        return Ok(None);
                    }
                    Some(value) => {
                        outer = Some(value);
                        break;
                    }
                }
            }
            if seen.contains(&current_row) {
                // Every row on a cycle, and every row nested in one, has no name.
                for step in &path {
                    self.remember(retain, step.row, None)?;
                }
                return Ok(None);
            }
            if path.len() == MAX_TYPE_NESTING_DEPTH {
                // The row the walk started from is nested past the cap.
                self.remember(retain, row, None)?;
                return Ok(None);
            }
            let (enclosing, namespace, name) = match self.read_link(link, retain, current_row)? {
                Some(step) => (
                    step.enclosing_row,
                    step.namespace.clone(),
                    step.name.clone(),
                ),
                None => {
                    self.remember(retain, current_row, None)?;
                    let visited: Vec<i64> = path.iter().map(|s| s.row).collect();
                    for visited_row in visited {
                        self.remember(retain, visited_row, None)?;
                    }
                    return Ok(None);
                }
            };
            seen.insert(current_row);
            path.push(Step {
                row: current_row,
                namespace,
                name,
            });
            current = enclosing;
        }
        // Name inward from the outermost row; a row past the cap, and every row
        // nested in it, has no name.
        let mut inner: Option<NamedRow> = outer;
        let mut exceeded = false;
        for step in path.into_iter().rev() {
            let depth = inner.as_ref().map(|value| value.depth).unwrap_or(0) + 1;
            exceeded = exceeded || depth > MAX_TYPE_NESTING_DEPTH;
            if exceeded {
                self.remember(retain, step.row, None)?;
                continue;
            }
            let mut hasher = Sha256::new();
            match &inner {
                None => {
                    hasher.update(TOP_LEVEL);
                }
                Some(value) => {
                    hasher.update(NESTED);
                    hasher.update(&value.digest);
                }
            }
            hasher.update(step.namespace.as_bytes());
            hasher.update(NAME_SEPARATOR);
            hasher.update(step.name.as_bytes());
            let digest = hasher.finalize().to_vec();
            inner = Some(NamedRow { digest, depth });
            self.remember(retain, step.row, inner.clone())?;
        }
        if exceeded {
            Ok(None)
        } else {
            Ok(inner.map(|value| value.digest))
        }
    }
}

/// Shared inputs the digest closures read.
struct DigestState<'a> {
    bytes: &'a [u8],
    layout: &'a ManagedMetadataLayout,
    issues: &'a RefCell<Vec<ManagedParseIssue>>,
    types: HashMap<String, &'a ParsedType>,
    nesting: &'a ManagedTypeNesting,
    references: &'a RefCell<ManagedTypeReferences>,
    definitions: NestedTypeDigests,
    reference_names: NestedTypeDigests,
    digests: HashMap<i64, Option<Vec<u8>>>,
}

/// A fatal failure a digest closure observed. The closure interface only yields
/// `Option<Vec<u8>>`, so a `resource-limit` (or internal) failure that the TS
/// would throw is retained here for the inspector to re-raise after member
/// parsing, reproducing the TS try/catch that turns it into an unavailable
/// result.
pub type DigestFault = Rc<RefCell<Option<ReadError>>>;

/// `managedTypeNameDigests(layout, issues, parsedTypes, reference)`.
///
/// Returns the `SignatureTypeName` closure over the shared `issues` and
/// `references` cells plus a [`DigestFault`] slot the caller checks after member
/// parsing.
#[allow(clippy::type_complexity)]
pub fn managed_type_name_digests<'a>(
    layout: &'a ManagedMetadataLayout,
    issues: &'a RefCell<Vec<ManagedParseIssue>>,
    parsed_types: &'a [ParsedType],
    nesting: &'a ManagedTypeNesting,
    references: &'a RefCell<ManagedTypeReferences>,
    bytes: &'a [u8],
) -> ReadResult<(impl FnMut(i64) -> Option<Vec<u8>> + 'a, DigestFault)> {
    // `managedDecodeBudget(layout).reserve(parsedTypes.types.length * 128, null)`.
    layout
        .budget()
        .reserve(parsed_types.len() as i64 * 128, None)?;
    let mut types: HashMap<String, &ParsedType> = HashMap::new();
    for type_row in parsed_types {
        types.insert(type_row.token.clone(), type_row);
    }
    let state = RefCell::new(DigestState {
        bytes,
        layout,
        issues,
        types,
        nesting,
        references,
        definitions: NestedTypeDigests::new(),
        reference_names: NestedTypeDigests::new(),
        digests: HashMap::new(),
    });
    let fault: DigestFault = Rc::new(RefCell::new(None));
    let closure_fault = Rc::clone(&fault);
    let closure = move |coded_index: i64| -> Option<Vec<u8>> {
        let mut state = state.borrow_mut();
        match resolve(&mut state, coded_index) {
            Ok(value) => value,
            Err(error) => {
                if closure_fault.borrow().is_none() {
                    *closure_fault.borrow_mut() = Some(error);
                }
                None
            }
        }
    };
    Ok((closure, fault))
}

/// `retain`: one 128-byte reservation against the shared budget.
fn retain_once(layout: &ManagedMetadataLayout) -> ReadResult<()> {
    layout.budget().reserve(128, None)?;
    Ok(())
}

fn resolve(state: &mut DigestState<'_>, coded_index: i64) -> ReadResult<Option<Vec<u8>>> {
    if let Some(cached) = state.digests.get(&coded_index) {
        return Ok(cached.clone());
    }
    state.layout.budget().reserve(256, None)?;
    // `codedIndex >>> 2` and `codedIndex & 3` on a 32-bit unsigned value.
    let unsigned = (coded_index as u32) as i64;
    let row = unsigned >> 2;
    let table = unsigned & 3;
    let digest = if table == 0 {
        definition_digest(state, row)?
    } else if table == 1 {
        reference_digest(state, row)?
    } else {
        None
    };
    state.digests.insert(coded_index, digest.clone());
    Ok(digest)
}

fn definition_digest(state: &mut DigestState<'_>, row: i64) -> ReadResult<Option<Vec<u8>>> {
    let layout = state.layout;
    let nesting = state.nesting;
    let issues = state.issues;
    let types = &state.types;
    let mut definitions = std::mem::replace(&mut state.definitions, NestedTypeDigests::new());
    let mut link = |row: i64| -> ReadResult<Option<TypeLink>> {
        if !nesting.complete {
            return Ok(None);
        }
        let token = metadata_token(TYPE_DEF, row);
        let type_row = types.get(&token).copied();
        let row_count = layout.table(TYPE_DEF).map(|t| t.row_count).unwrap_or(0);
        if type_row.is_none() && (row < 1 || row > row_count) {
            read_managed_value(
                || -> ReadResult<()> {
                    Err(managed_failure(
                        "invalid-row",
                        format!("metadata.signature.type:{TYPE_DEF}:{row}"),
                        format!("Signature references an unavailable TypeDef row {row}"),
                        None,
                    )
                    .into())
                },
                &mut issues.borrow_mut(),
            )?;
            return Ok(None);
        }
        let type_row = match type_row {
            Some(type_row) => type_row,
            None => return Ok(None),
        };
        let enclosing_row = nesting.enclosing.get(&row).copied();
        // ECMA-335 TypeAttributes.VisibilityMask: 0/1 top-level, 2..7 nested.
        let nested = (type_row.flags & 0x7) >= 2;
        if nested != enclosing_row.is_some() {
            layout
                .budget()
                .reserve(512, Some(type_row.row_offset as u64))?;
            let token = type_row.token.clone();
            let row_offset = type_row.row_offset;
            read_managed_value(
                || -> ReadResult<()> {
                    Err(managed_failure(
                        "invalid-row",
                        format!("metadata.TypeDef:{token}"),
                        if nested {
                            format!("Nested TypeDef {token} has no NestedClass enclosing entry")
                        } else {
                            format!("Top-level TypeDef {token} has a NestedClass enclosing entry")
                        },
                        Some(row_offset as u64),
                    )
                    .into())
                },
                &mut issues.borrow_mut(),
            )?;
            return Ok(None);
        }
        Ok(Some(TypeLink {
            namespace: type_row.namespace.clone(),
            name: type_row.name.clone(),
            enclosing_row,
        }))
    };
    let mut retain = || retain_once(layout);
    let result = definitions.digest(&mut link, &mut retain, row);
    state.definitions = definitions;
    result
}

fn reference_digest(state: &mut DigestState<'_>, row: i64) -> ReadResult<Option<Vec<u8>>> {
    let layout = state.layout;
    let bytes = state.bytes;
    let issues = state.issues;
    let references = state.references;
    let mut reference_names =
        std::mem::replace(&mut state.reference_names, NestedTypeDigests::new());
    let mut link = |row: i64| -> ReadResult<Option<TypeLink>> {
        let value = references
            .borrow_mut()
            .lookup(bytes, layout, &mut issues.borrow_mut(), row)?;
        Ok(match value {
            Some(value) if value.scope_valid => Some(TypeLink {
                namespace: value.namespace,
                name: value.name,
                enclosing_row: value.enclosing_row,
            }),
            _ => None,
        })
    };
    let mut retain = || retain_once(layout);
    let result = reference_names.digest(&mut link, &mut retain, row);
    state.reference_names = reference_names;
    result
}
