//! One structured instruction observation from the read-only decompiler.

use anyhow::{Context, Result, ensure};
use ghidra_decompiler::opcodes::OpCode;
use ghidra_decompiler::program::{Instruction, InstructionPcode, PcodeOperation, Program};
use serde_json::{Value, json};

use crate::decompiler_facts::DecompilerFacts;
use crate::protocol::address;

fn input_address(input: &Value) -> Result<u64> {
    let address = input
        .get("address")
        .and_then(Value::as_str)
        .context("instruction address is required")?;
    let value = crate::protocol::parse_address(address)
        .context("instruction address must be canonical lowercase hexadecimal")?;
    ensure!(
        crate::protocol::address(value) == address,
        "instruction address is not canonical"
    );
    Ok(value)
}

fn bytes_hex(instruction: &Instruction) -> String {
    instruction
        .bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn operands(_instruction: &Instruction) -> Value {
    // The worker API exposes the raw operand string, but does not expose the
    // decoder's operand component/type model. Returning an empty structured
    // list keeps that absence explicit instead of inventing a provider type.
    json!([])
}

fn direct_target(operation: &PcodeOperation) -> Option<u64> {
    if !matches!(
        operation.opcode,
        OpCode::Call | OpCode::Branch | OpCode::Cbranch
    ) {
        return None;
    }
    operation
        .inputs
        .first()
        .filter(|input| matches!(input.space.as_str(), "ram" | "default"))
        .map(|input| input.offset)
}

fn flow(pcode: &InstructionPcode) -> Value {
    let mut kinds = Vec::new();
    let mut conditional = false;
    let mut computed = false;
    let mut destinations = Vec::new();
    let mut evidence = Vec::new();
    let mut unknown_control = false;

    for operation in &pcode.operations {
        let is_internal_branch = matches!(operation.opcode, OpCode::Branch | OpCode::Cbranch)
            && operation
                .inputs
                .first()
                .is_some_and(|input| input.space == "const");
        let candidate = match operation.opcode {
            OpCode::Call if direct_target(operation).is_some() => Some(("call", false)),
            OpCode::Callind => Some(("call", false)),
            OpCode::Branch if direct_target(operation).is_some() => Some(("jump", false)),
            OpCode::Branchind => Some(("jump", false)),
            OpCode::Cbranch if direct_target(operation).is_some() => Some(("jump", true)),
            OpCode::Return => Some(("return", false)),
            _ => None,
        };
        let Some((operation_kind, operation_conditional)) = candidate else {
            if matches!(
                operation.opcode,
                OpCode::Call | OpCode::Branch | OpCode::Cbranch
            ) && !is_internal_branch
            {
                unknown_control = true;
            }
            continue;
        };
        if !kinds.contains(&operation_kind) {
            kinds.push(operation_kind);
        }
        conditional |= operation_conditional;
        computed |= matches!(operation.opcode, OpCode::Callind | OpCode::Branchind);
        if let Some(target) = direct_target(operation) {
            destinations.push(address(target));
        } else if matches!(operation.opcode, OpCode::Callind | OpCode::Branchind) {
            computed = true;
        }
        evidence.push(json!({
            "source": "ghidra-pcode",
            "value": format!("{:?}", operation.opcode),
        }));
    }

    let kind = match kinds.as_slice() {
        _ if unknown_control => "unavailable",
        [] => "fallthrough",
        [kind] => *kind,
        _ => "unavailable",
    };

    json!({
        "kind": kind,
        "conditional": conditional,
        "computed": computed,
        "direct_destinations": destinations,
        "classification_evidence": evidence,
    })
}

fn references(pcode: &InstructionPcode) -> Vec<Value> {
    pcode
        .operations
        .iter()
        .filter_map(|operation| {
            let (kind, call, jump) = match operation.opcode {
                OpCode::Call => ("call", true, false),
                OpCode::Callind => return None,
                OpCode::Branch => ("jump", false, true),
                OpCode::Cbranch => ("conditional_jump", false, true),
                _ => return None,
            };
            let target = direct_target(operation).map(address)?;
            Some(json!({
                "target_address": target,
                "type": kind,
                "call": call,
                "jump": jump,
                "indirect": operation.opcode == OpCode::Callind,
                "computed": operation.opcode == OpCode::Callind,
                "operand_index": -1,
                "source_address": address(pcode.address),
                "data": false,
                "read": false,
                "write": false,
                "primary": null,
                "provenance": "ghidra-pcode",
                "source": "ghidra-pcode",
            }))
        })
        .collect()
}

fn undecodable(address_value: u64, language: &str, reason: String) -> Value {
    json!({
        "address": address(address_value),
        "status": "undecodable",
        "procedure": null,
        "architecture": language,
        "mode": "unknown",
        "decoder_context": [],
        "bytes": null,
        "length": null,
        "mnemonic": null,
        "raw_disassembly": null,
        "operands": [],
        "flow": {
            "kind": "unavailable",
            "conditional": false,
            "computed": false,
            "direct_destinations": [],
            "classification_evidence": [],
        },
        "references": [],
        "incoming_references": null,
        "limitations": [format!("The Ghidra decoder could not decode the requested address: {reason}")],
    })
}

fn decoded_without_pcode(instruction: &Instruction, language: &str, reason: String) -> Value {
    json!({
        "address": address(instruction.address),
        "status": "decoded",
        "procedure": null,
        "architecture": language,
        "mode": "unknown",
        "decoder_context": [],
        "bytes": bytes_hex(instruction),
        "length": instruction.length,
        "mnemonic": instruction.mnemonic,
        "raw_disassembly": format!("{} {}", instruction.mnemonic, instruction.operands).trim().to_owned(),
        "operands": operands(instruction),
        "flow": {
            "kind": "unavailable",
            "conditional": false,
            "computed": false,
            "direct_destinations": [],
            "classification_evidence": [],
        },
        "references": [],
        "incoming_references": null,
        "limitations": [
            format!("The instruction decoded, but p-code was unavailable: {reason}"),
            "Operand components are unavailable from this worker API; use raw_disassembly for the decoder's operand text.",
        ],
    })
}

fn non_code(address_value: u64, language: &str, mapped: bool) -> Value {
    json!({
        "address": crate::protocol::address(address_value),
        "status": if mapped { "data" } else { "outside-memory" },
        "procedure": null,
        "architecture": language,
        "mode": "unknown",
        "decoder_context": [],
        "bytes": null,
        "length": null,
        "mnemonic": null,
        "raw_disassembly": null,
        "operands": [],
        "flow": {"kind": "unavailable", "conditional": false, "computed": false, "direct_destinations": [], "classification_evidence": []},
        "references": [],
        "incoming_references": null,
        "limitations": [if mapped { "The requested address is in a validated mapped object range but not executable code; instruction decoding was not attempted." } else { "The requested address is outside validated mapped object ranges." }],
    })
}

pub fn inspect(
    program: &Program,
    facts: &DecompilerFacts,
    input: &Value,
    language: &str,
    mapped_ranges: &[std::ops::Range<u64>],
) -> Result<Value> {
    let requested = input_address(input)?;
    if !facts.is_code(requested, 1) {
        let mapped = mapped_ranges.iter().any(|range| range.contains(&requested));
        return Ok(non_code(requested, language, mapped));
    }
    let instruction = match program.disassemble(requested, 1) {
        Ok(mut items) => items.pop(),
        Err(error) => {
            return Ok(undecodable(requested, language, error.to_string()));
        }
    };
    let Some(instruction) = instruction else {
        return Ok(undecodable(
            requested,
            language,
            "the decoder returned no instruction".to_owned(),
        ));
    };
    ensure!(
        instruction.address == requested,
        "The decoder returned an instruction at an unexpected address"
    );
    ensure!(
        instruction.length > 0 && instruction.bytes.len() == instruction.length,
        "The decoder returned inconsistent instruction bytes"
    );
    if !facts.is_code(requested, instruction.length as u64) {
        return Ok(undecodable(
            requested,
            language,
            "the decoded instruction extends beyond the validated executable section".to_owned(),
        ));
    }
    let pcode = match program.pcode(requested, 1) {
        Ok(mut items) => items.pop(),
        Err(error) => {
            return Ok(decoded_without_pcode(
                &instruction,
                language,
                error.to_string(),
            ));
        }
    };
    let Some(pcode) = pcode else {
        return Ok(decoded_without_pcode(
            &instruction,
            language,
            "the decoder returned no p-code operations".to_owned(),
        ));
    };
    ensure!(
        pcode.address == requested && pcode.length == instruction.length,
        "The decoder returned inconsistent p-code coordinates"
    );
    Ok(json!({
        "address": address(instruction.address),
        "status": "decoded",
        "procedure": null,
        "architecture": language,
        "mode": "unknown",
        "decoder_context": [],
        "bytes": bytes_hex(&instruction),
        "length": instruction.length,
        "mnemonic": instruction.mnemonic,
        "raw_disassembly": format!("{} {}", instruction.mnemonic, instruction.operands).trim().to_owned(),
        "operands": operands(&instruction),
        "flow": flow(&pcode),
        "references": references(&pcode),
        "incoming_references": null,
        "limitations": [
            "Procedure identity, decoder context and incoming references are unavailable for a single instruction read.",
            "Operand components are unavailable from this worker API; use raw_disassembly for the decoder's operand text.",
            "Control-flow targets in unsupported p-code address spaces remain unavailable.",
        ],
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_decompiler::program::PcodeVarnode;

    fn operation(opcode: OpCode, space: &str, offset: u64) -> PcodeOperation {
        PcodeOperation {
            opcode,
            output: None,
            inputs: vec![PcodeVarnode {
                space: space.to_owned(),
                offset,
                size: 8,
            }],
            space: None,
        }
    }

    #[test]
    fn const_space_branch_is_not_reported_as_machine_jump() {
        let pcode = InstructionPcode {
            address: 0x1000,
            length: 2,
            operations: vec![operation(OpCode::Branch, "const", 0x42)],
        };

        let flow = flow(&pcode);

        assert_eq!(flow["kind"], "fallthrough");
        assert_eq!(flow["direct_destinations"], json!([]));
        assert_eq!(flow["computed"], false);
    }

    #[test]
    fn register_indirect_branch_is_computed_without_target() {
        let pcode = InstructionPcode {
            address: 0x1000,
            length: 2,
            operations: vec![operation(OpCode::Branchind, "register", 0x42)],
        };

        let flow = flow(&pcode);

        assert_eq!(flow["kind"], "jump");
        assert_eq!(flow["computed"], true);
        assert_eq!(flow["direct_destinations"], json!([]));
    }

    #[test]
    fn indirect_ram_call_is_computed_without_target() {
        let pcode = InstructionPcode {
            address: 0x1000,
            length: 2,
            operations: vec![operation(OpCode::Callind, "ram", 0x2000)],
        };

        let flow = flow(&pcode);

        assert_eq!(flow["kind"], "call");
        assert_eq!(flow["computed"], true);
        assert_eq!(flow["direct_destinations"], json!([]));
        assert!(references(&pcode).is_empty());
    }

    #[test]
    fn direct_ram_call_is_the_only_call_target_form() {
        let pcode = InstructionPcode {
            address: 0x1000,
            length: 5,
            operations: vec![operation(OpCode::Call, "ram", 0x2000)],
        };

        let flow = flow(&pcode);
        let references = references(&pcode);

        assert_eq!(flow["direct_destinations"], json!(["0x2000"]));
        assert_eq!(references.len(), 1);
        assert_eq!(references[0]["target_address"], "0x2000");
        assert_eq!(references[0]["operand_index"], -1);
    }

    #[test]
    fn missing_or_const_call_target_is_unavailable() {
        let missing_target = InstructionPcode {
            address: 0x1000,
            length: 4,
            operations: vec![PcodeOperation {
                opcode: OpCode::Call,
                output: None,
                inputs: Vec::new(),
                space: None,
            }],
        };
        let const_target = InstructionPcode {
            address: 0x1004,
            length: 4,
            operations: vec![operation(OpCode::Call, "const", 0x42)],
        };

        assert_eq!(flow(&missing_target)["kind"], "unavailable");
        assert_eq!(flow(&const_target)["kind"], "unavailable");
    }
}
