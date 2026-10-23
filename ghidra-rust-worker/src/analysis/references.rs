//! Derived references for every frozen inventory function.
//!
//! The engine has no reference manager, so references are derived from
//! per-instruction p-code over each function's extent (from its entry up to
//! the next inventory entry, inside executable sections). Direct call and
//! branch targets come from the operation itself. Data references come from a
//! small forward constant propagation over register and temporary varnodes:
//! it resolves address constants built over several instructions (AArch64
//! `adrp`+`add`, PC-relative x86 operands) and reports the address that a
//! load, store, call argument or other use consumed. It does not follow flow,
//! resolve indirect targets, or track values through memory.
use std::collections::HashMap;
use std::ops::Range;

use ghidra_decompiler::opcodes::OpCode;
use ghidra_decompiler::program::{PcodeVarnode, Program};

use crate::decompiler_facts::DecompilerFacts;

/// Instructions scanned per function; matches the per-function flow cap.
pub(crate) const MAX_EXTENT_INSTRUCTIONS: usize = 65_536;

/// How a source instruction refers to its target.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub(crate) enum Kind {
    /// Direct call.
    Call = 1,
    /// Unconditional branch to another inventory entry (tail call).
    Jump = 2,
    /// Conditional branch to another inventory entry.
    ConditionalJump = 3,
    /// Address read by a load.
    Read = 4,
    /// Address written by a store.
    Write = 5,
    /// Address constant consumed by another use (argument, stored pointer).
    Address = 6,
    /// Indirect call whose target is not resolved; the target is 0.
    IndirectCall = 7,
}

impl Kind {
    pub(crate) fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            1 => Self::Call,
            2 => Self::Jump,
            3 => Self::ConditionalJump,
            4 => Self::Read,
            5 => Self::Write,
            6 => Self::Address,
            7 => Self::IndirectCall,
            _ => return None,
        })
    }

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Call => "call",
            Self::Jump => "jump",
            Self::ConditionalJump => "conditional_jump",
            Self::Read => "read",
            Self::Write => "write",
            Self::Address => "address",
            Self::IndirectCall => "indirect_call",
        }
    }
}

/// One derived reference from an instruction in `function`.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct Reference {
    pub function: u64,
    pub source: u64,
    pub target: u64,
    pub kind: Kind,
}

/// Address ranges a data reference may name: every object-file section.
pub(crate) struct Mapped {
    ranges: Vec<Range<u64>>,
}

impl Mapped {
    pub(crate) fn new(mut ranges: Vec<Range<u64>>) -> Self {
        ranges.retain(|range| !range.is_empty());
        ranges.sort_by_key(|range| range.start);
        Self { ranges }
    }

    fn contains(&self, address: u64) -> bool {
        let index = self.ranges.partition_point(|range| range.start <= address);
        index > 0 && self.ranges[index - 1].contains(&address)
    }
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
enum Space {
    Register,
    Unique,
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
struct Location {
    space: Space,
    offset: u64,
    size: u32,
}

fn location(varnode: &PcodeVarnode) -> Option<Location> {
    let space = match varnode.space.as_str() {
        "register" => Space::Register,
        "unique" => Space::Unique,
        _ => return None,
    };
    Some(Location {
        space,
        offset: varnode.offset,
        size: varnode.size,
    })
}

fn mask(value: u64, size: u32) -> u64 {
    if size >= 8 { value } else { value & ((1_u64 << (size * 8)) - 1) }
}

/// Constant state for one linear pass over a function.
struct Values {
    known: HashMap<Location, u64>,
    /// Mapped address constants held in registers, not yet consumed:
    /// `(producing instruction, address)`.
    pending: HashMap<Location, (u64, u64)>,
}

impl Values {
    fn value(&self, varnode: &PcodeVarnode) -> Option<u64> {
        if varnode.space == "const" {
            return Some(varnode.offset);
        }
        location(varnode).and_then(|location| self.known.get(&location).copied())
    }

    fn clear_temporaries(&mut self) {
        self.known.retain(|location, _| location.space == Space::Register);
        self.pending.retain(|location, _| location.space == Space::Register);
    }
}

struct Sweep<'a> {
    function: u64,
    mapped: &'a Mapped,
    values: Values,
    output: Vec<Reference>,
}

impl Sweep<'_> {
    fn push(&mut self, source: u64, target: u64, kind: Kind) {
        self.output.push(Reference {
            function: self.function,
            source,
            target,
            kind,
        });
    }

    /// Report every pending constant as consumed by a use.
    fn flush(&mut self) {
        let pending: Vec<(u64, u64)> = self.values.pending.drain().map(|(_, value)| value).collect();
        for (source, target) in pending {
            self.push(source, target, Kind::Address);
        }
    }

    /// Inputs consumed by an operation that does not derive a new address
    /// report their pending constants.
    fn consume(&mut self, inputs: &[PcodeVarnode]) {
        for input in inputs {
            if let Some(location) = location(input)
                && let Some((source, target)) = self.values.pending.remove(&location)
            {
                self.push(source, target, Kind::Address);
            }
        }
    }

    /// Inputs that derive another value drop their pending constants; the
    /// derived value carries the address forward.
    fn derive_from(&mut self, inputs: &[PcodeVarnode]) {
        for input in inputs {
            if let Some(location) = location(input) {
                self.values.pending.remove(&location);
            }
        }
    }

    fn reset(&mut self) {
        self.flush();
        self.values.known.clear();
    }
}

fn neutral(opcode: OpCode) -> bool {
    matches!(
        opcode,
        OpCode::IntEqual
            | OpCode::IntNotequal
            | OpCode::IntSless
            | OpCode::IntSlessequal
            | OpCode::IntLess
            | OpCode::IntLessequal
            | OpCode::IntCarry
            | OpCode::IntScarry
            | OpCode::IntSborrow
            | OpCode::BoolNegate
            | OpCode::BoolXor
            | OpCode::BoolAnd
            | OpCode::BoolOr
            | OpCode::Popcount
            | OpCode::Lzcount
    )
}

fn arithmetic(opcode: OpCode, inputs: &[Option<u64>], size: u32) -> Option<u64> {
    let first = (*inputs.first()?)?;
    let second = || inputs.get(1).copied().flatten();
    let value = match opcode {
        OpCode::Copy | OpCode::IntZext => first,
        OpCode::IntSext => first,
        OpCode::IntAdd | OpCode::Ptrsub => first.wrapping_add(second()?),
        OpCode::IntSub => first.wrapping_sub(second()?),
        OpCode::IntAnd => first & second()?,
        OpCode::IntOr => first | second()?,
        OpCode::IntLeft => first.checked_shl(u32::try_from(second()?).ok()?)?,
        OpCode::Ptradd => first.wrapping_add(second()?.wrapping_mul(inputs.get(2).copied().flatten()?)),
        OpCode::Subpiece => first.checked_shr(u32::try_from(second()?.checked_mul(8)?).ok()?)?,
        _ => return None,
    };
    Some(mask(value, size))
}

/// Derive the references of one function. `entry..end` is the extent
/// bounded by the next inventory entry; `starts` is the sorted inventory.
pub(crate) fn sweep(
    program: &Program,
    facts: &DecompilerFacts,
    mapped: &Mapped,
    starts: &[u64],
    entry: u64,
) -> Vec<Reference> {
    let next = starts.partition_point(|start| *start <= entry);
    let end = starts.get(next).copied().unwrap_or(u64::MAX);
    let mut sweep = Sweep {
        function: entry,
        mapped,
        values: Values {
            known: HashMap::new(),
            pending: HashMap::new(),
        },
        output: Vec::new(),
    };
    let mut address = entry;
    for _ in 0..MAX_EXTENT_INSTRUCTIONS {
        // Decoding bytes outside executable sections corrupts the engine's
        // later decodes (see `DecompilerFacts`).
        if address >= end || !facts.is_code(address, 1) {
            break;
        }
        let Some(instruction) = program.pcode(address, 1).ok().and_then(|mut list| list.pop()) else {
            break;
        };
        if instruction.length == 0 {
            break;
        }
        sweep.values.clear_temporaries();
        for operation in &instruction.operations {
            let site = instruction.address;
            let direct = operation
                .inputs
                .first()
                .filter(|target| target.space != "const")
                .map(|target| target.offset);
            match operation.opcode {
                OpCode::Call | OpCode::Callind => {
                    match (operation.opcode, direct) {
                        (OpCode::Call, Some(target)) => sweep.push(site, target, Kind::Call),
                        (OpCode::Call, None) => {}
                        _ => sweep.push(site, 0, Kind::IndirectCall),
                    }
                    // The return address a call instruction writes (for
                    // example AArch64 `x30`) is not a data reference.
                    sweep.values.pending.retain(|_, (source, _)| *source != site);
                    sweep.reset();
                    continue;
                }
                OpCode::Branch | OpCode::Cbranch => {
                    if let Some(target) = direct
                        && target != entry
                        && starts.binary_search(&target).is_ok()
                    {
                        let kind = if operation.opcode == OpCode::Branch {
                            Kind::Jump
                        } else {
                            Kind::ConditionalJump
                        };
                        sweep.push(site, target, kind);
                    }
                    if operation.opcode == OpCode::Branch {
                        sweep.reset();
                    }
                    continue;
                }
                OpCode::Branchind | OpCode::Return => {
                    sweep.reset();
                    continue;
                }
                OpCode::Load => {
                    if let Some(pointer) = operation.inputs.get(1)
                        && let Some(target) = sweep.values.value(pointer)
                        && sweep.mapped.contains(target)
                    {
                        sweep.push(site, target, Kind::Read);
                    }
                    sweep.derive_from(&operation.inputs);
                }
                OpCode::Store => {
                    if let Some(pointer) = operation.inputs.get(1)
                        && let Some(target) = sweep.values.value(pointer)
                        && sweep.mapped.contains(target)
                    {
                        sweep.push(site, target, Kind::Write);
                    }
                    sweep.derive_from(operation.inputs.get(1..2).unwrap_or_default());
                    if let Some(stored) = operation.inputs.get(2)
                        && let Some(value) = sweep.values.value(stored)
                        && sweep.mapped.contains(value)
                    {
                        sweep.derive_from(std::slice::from_ref(stored));
                        sweep.push(site, value, Kind::Address);
                    }
                    continue;
                }
                _ => {}
            }
            // Flag and comparison results do not move an address; they
            // neither consume nor derive the constants they read.
            if neutral(operation.opcode) {
                if let Some(location) = operation.output.as_ref().and_then(location) {
                    sweep.values.known.remove(&location);
                    sweep.values.pending.remove(&location);
                }
                continue;
            }
            let Some(output) = operation.output.as_ref() else {
                sweep.consume(&operation.inputs);
                continue;
            };
            let values: Vec<Option<u64>> =
                operation.inputs.iter().map(|input| sweep.values.value(input)).collect();
            let derived = if operation.opcode == OpCode::Load {
                None
            } else {
                arithmetic(operation.opcode, &values, output.size)
            };
            if derived.is_some() {
                sweep.derive_from(&operation.inputs);
            } else if operation.opcode != OpCode::Load {
                sweep.consume(&operation.inputs);
            }
            let Some(location) = location(output) else {
                continue;
            };
            // An overwritten register's unused constant is not a reference.
            sweep.values.pending.remove(&location);
            match derived {
                Some(value) => {
                    sweep.values.known.insert(location, value);
                    if sweep.mapped.contains(value) {
                        sweep.values.pending.insert(location, (site, value));
                    }
                }
                None => {
                    sweep.values.known.remove(&location);
                }
            }
        }
        address += instruction.length as u64;
    }
    sweep.flush();
    sweep.output.sort();
    sweep.output.dedup_by(|left, right| {
        left.source == right.source && left.target == right.target && left.kind == right.kind
    });
    sweep.output
}
