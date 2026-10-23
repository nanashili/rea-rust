use std::time::{Duration, Instant};

use ghidra_decompiler::address::Address;
use ghidra_decompiler::arena::Arena;
use ghidra_decompiler::database::SymbolId;
use ghidra_decompiler::op::PcodeOpBank;
use ghidra_decompiler::opcodes::OpCode;
use ghidra_decompiler::program::Program;
use ghidra_decompiler::varnode::VarnodeBank;

use crate::decompiler_facts::DecompilerFacts;

/// Decompile attempts before a Program is rebuilt. Per-function analysis
/// arenas are released after each decompile, so retained growth is the
/// engine's symbol, type and comment state (about 0.5 MiB per function on a
/// large Mach-O target).
pub(crate) const MAX_DECOMPILE_ATTEMPTS: usize = 512;
pub(crate) const IDLE_RELEASE_AFTER: Duration = Duration::from_secs(30);

/// Instructions scanned for tail branches; matches the per-function flow cap.
const MAX_EXTENT_INSTRUCTIONS: usize = 65_536;

pub(crate) struct ProgramRetention {
    program: Program,
    decompile_attempts: usize,
    last_activity: Instant,
}

impl ProgramRetention {
    pub(crate) fn new(program: Program) -> Self {
        Self {
            program,
            decompile_attempts: 0,
            last_activity: Instant::now(),
        }
    }

    /// Read-only access for disassembly and p-code; marks activity.
    pub(crate) fn program(&mut self) -> &Program {
        self.last_activity = Instant::now();
        &self.program
    }

    pub(crate) fn decompile_attempts_exhausted(&self) -> bool {
        self.decompile_attempts >= MAX_DECOMPILE_ATTEMPTS
    }

    pub(crate) fn time_until_idle_release(&self, now: Instant) -> Duration {
        IDLE_RELEASE_AFTER.saturating_sub(now.saturating_duration_since(self.last_activity))
    }

    pub(crate) fn should_release(&self, now: Instant) -> bool {
        self.decompile_attempts_exhausted() || self.time_until_idle_release(now).is_zero()
    }

    /// Decompile one inventory entry. `starts` is the sorted frozen inventory;
    /// an unconditional branch from this entry's extent to another entry is a
    /// tail call, matching Java Ghidra's function-boundary treatment, so the
    /// other function's body is not inlined.
    pub(crate) fn decompile(
        &mut self,
        address: u64,
        starts: &[u64],
        facts: &DecompilerFacts,
    ) -> ghidra_decompiler::error::Result<String> {
        self.decompile_attempts += 1;
        mark_tail_calls(&mut self.program, address, starts, facts);
        let result = self.program.decompile(address);
        release_analysis_arenas(&mut self.program, address);
        self.last_activity = Instant::now();
        result
    }
}

fn function_symbol(program: &mut Program, entry: u64) -> Option<(SymbolId, Address)> {
    let architecture = program.architecture();
    let space = architecture.manager.get_default_code_space()?;
    let address = Address::new(space, entry);
    let symbol = architecture.symboltab.as_ref().and_then(|database| {
        let scope = database.get_global_scope()?;
        database.scope_query_function(scope, &address)
    })?;
    Some((symbol, address))
}

/// Insert CALL_RETURN flow overrides for unconditional branches from
/// `[entry, next entry)` to another inventory entry. Conditional branches
/// cannot carry this override in the engine and are left unchanged; entries
/// without a loader symbol are decompiled without overrides.
fn mark_tail_calls(program: &mut Program, entry: u64, starts: &[u64], facts: &DecompilerFacts) {
    let next = starts.partition_point(|start| *start <= entry);
    let Some(&end) = starts.get(next) else {
        return;
    };
    let mut branches = Vec::new();
    let mut address = entry;
    for _ in 0..MAX_EXTENT_INSTRUCTIONS {
        // Stop at the end of executable sections: decoding other bytes
        // corrupts the engine's later decodes (see `DecompilerFacts`).
        if address >= end || !facts.is_code(address, 1) {
            break;
        }
        let Some(instruction) = program.pcode(address, 1).ok().and_then(|mut list| list.pop()) else {
            break;
        };
        for operation in &instruction.operations {
            if operation.opcode != OpCode::Branch {
                continue;
            }
            let Some(destination) = operation.inputs.first() else {
                continue;
            };
            if destination.space != "const"
                && destination.offset != entry
                && starts.binary_search(&destination.offset).is_ok()
            {
                branches.push(instruction.address);
            }
        }
        if instruction.length == 0 {
            break;
        }
        address += instruction.length as u64;
    }
    if branches.is_empty() {
        return;
    }
    let Some((symbol, function_address)) = function_symbol(program, entry) else {
        return;
    };
    let Some(space) = function_address.get_space().cloned() else {
        return;
    };
    let _ = program.architecture().with_function(symbol, |function, _| {
        for branch in &branches {
            function
                .get_override()
                .insert_flow_override(&Address::new(space.clone(), *branch), "callreturn")?;
        }
        Ok(())
    });
}

/// `Program::decompile` ends with `clear_analysis`, which empties the
/// function's p-code, varnode, high-variable and call-spec arenas but keeps
/// every slot. Replace the emptied containers so a function's past analysis
/// is not retained and later clears do not scan stale slots. This changes no
/// analysis input: the containers are empty, and fresh ones are equivalent.
fn release_analysis_arenas(program: &mut Program, entry: u64) {
    let Some((symbol, _)) = function_symbol(program, entry) else {
        return;
    };
    // A failure leaves the cleared containers in place, which is correct but
    // keeps their capacity; the attempt bound still recycles the Program.
    let _ = program.architecture().with_function(symbol, |function, architecture| {
        let Some(translate) = architecture.translate.as_deref() else {
            return Ok(());
        };
        function.obank = PcodeOpBank::new();
        function.vbank = VarnodeBank::new(&architecture.manager, translate);
        if function.highs.is_empty() {
            function.highs = Arena::new();
        }
        if function.groups.is_empty() {
            function.groups = Arena::new();
        }
        if function.callspecs.is_empty() && function.qlst.is_empty() {
            function.callspecs = Arena::new();
        }
        Ok(())
    });
}
