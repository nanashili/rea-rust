#!/usr/bin/env python3
"""Summarize bounded native-candidate qualification receipts.

This reads full local MCP receipts from a supplemental run and emits only counts,
hashes, statuses, limits, and candidate addresses. It never copies assembly,
pseudocode, strings, or target source into the output.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def response_value(call: dict[str, Any]) -> Any:
    result = call.get("response", {}).get("result", {})
    return result.get("structuredContent")


def calls_in(work_dir: Path, workflow: str) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    calls: list[dict[str, Any]] = []
    load_errors: list[dict[str, str]] = []
    for round_dir in sorted(work_dir.glob(f"{workflow}-round-*")):
        for path in sorted(round_dir.glob("call-*.json")):
            try:
                call = json.loads(path.read_text())
            except OSError as exc:
                load_errors.append({"file": path.name, "error": type(exc).__name__})
                continue
            except json.JSONDecodeError as exc:
                load_errors.append({"file": path.name, "error": "JSONDecodeError"})
                continue
            call["_round"] = round_dir.name.rsplit("-round-", 1)[-1]
            calls.append(call)
    return calls, load_errors


def call_matches(call: dict[str, Any], operation: str, address: str | None = None) -> bool:
    request = call.get("request", {}).get("params", {}).get("arguments", {})
    name = call.get("request", {}).get("params", {}).get("name")
    if name != operation:
        return False
    if address is None:
        return True
    return request.get("procedure") == address or request.get("address") == address


def bounded_error(call: dict[str, Any]) -> str | None:
    error = call.get("error")
    if isinstance(error, str):
        return error[:240]
    result = response_value(call)
    if isinstance(result, dict):
        failure = result.get("error")
        if isinstance(failure, str):
            return failure[:240]
    return None


def pseudo_fact(call: dict[str, Any]) -> dict[str, Any]:
    result = response_value(call)
    value = result.get("normalized_result") if isinstance(result, dict) else None
    if isinstance(value, str):
        text = value
    elif isinstance(value, dict):
        text = value.get("pseudocode") if isinstance(value.get("pseudocode"), str) else ""
    else:
        text = ""
    lower = text.lower()
    nonempty = bool(text.strip())
    bad = bool(re.search(r"bad instruction|invalid instruction|halted|decode failed", lower))
    trivial_return = bool(re.match(r"^\s*(?:[a-z_][\w:<>]*\s+)?[\w:<>$]+\s*\([^)]*\)\s*\{\s*return;?\s*\}\s*$", text, re.S))
    return {
        "status": call.get("status"),
        "nonempty": nonempty,
        "length": len(text),
        "sha256": digest(text) if text else None,
        "bad_instruction_or_halt": bad,
        "trivial_return": trivial_return,
        "useful": nonempty and len(text) >= 32 and not bad and not trivial_return,
        "error": bounded_error(call),
    }


def candidate_fact(calls: list[dict[str, Any]], candidate: dict[str, Any]) -> dict[str, Any]:
    address = candidate["address"]
    observed_extent = candidate.get("independent_extent_bytes")
    source = candidate.get("source", "")

    # A distance to the next inventory/symbol start is an interval, not proof
    # that the current function ends there. A function-start record has the
    # same limitation. Keep those observations visible, but do not qualify
    # them as independently established function extents.
    if observed_extent is None:
        extent_basis = "unknown"
    elif "unwind_info function start" in source:
        extent_basis = "function_start_only"
    else:
        extent_basis = "adjacent_known_start_interval"
    extent = None
    assembly = next((c for c in calls if call_matches(c, "procedure_assembly", address)), None)
    instruction = next((c for c in calls if call_matches(c, "read_function_instructions", address)), None)
    pseudos = [c for c in calls if call_matches(c, "procedure_pseudo_code", address)]
    batch = next((c for c in calls if call_matches(c, "batch_decompile")), None)

    assembly_result = response_value(assembly) if assembly else None
    assembly_text = assembly_result.get("normalized_result") if isinstance(assembly_result, dict) else None
    if not isinstance(assembly_text, str):
        assembly_text = ""

    instruction_result = response_value(instruction) if instruction else None
    instruction_value = instruction_result.get("normalized_result") if isinstance(instruction_result, dict) else None
    instructions = instruction_value.get("instructions") if isinstance(instruction_value, dict) else None
    if not isinstance(instructions, list):
        instructions = []

    pseudo_facts = [pseudo_fact(c) for c in pseudos]
    pseudo_hashes = [item["sha256"] for item in pseudo_facts if item["sha256"]]
    batch_result = response_value(batch) if batch else None
    batch_items = batch_result.get("normalized_result", {}).get("items", []) if isinstance(batch_result, dict) else []
    batch_item = next((item for item in batch_items if item.get("address") == address), None) if isinstance(batch_items, list) else None
    batch_pseudo = batch_item.get("pseudocode") if isinstance(batch_item, dict) else None

    qualification_reasons: list[str] = []
    if not assembly or assembly.get("status") != "success" or not assembly_text.strip():
        qualification_reasons.append("assembly_missing_failed_or_empty")
    if not instruction or instruction.get("status") != "success":
        qualification_reasons.append("instruction_read_missing_or_failed")
    elif len(instructions) < 8:
        qualification_reasons.append("fewer_than_8_instructions")
    if extent is None or extent < 32:
        qualification_reasons.append("independent_function_extent_not_established")
    if len(pseudo_facts) != 3:
        qualification_reasons.append("pseudocode_repeat_count_not_3")
    elif not all(item["status"] == "success" and item["useful"] for item in pseudo_facts):
        qualification_reasons.append("pseudocode_failed_trivial_or_decode_halted")
    elif len(set(pseudo_hashes)) != 1:
        qualification_reasons.append("pseudocode_repeat_hashes_differ")
    if not isinstance(batch_item, dict) or batch.get("status") != "success" or batch_item.get("status") != "ok" or not isinstance(batch_pseudo, str) or not batch_pseudo.strip():
        qualification_reasons.append("batch_decompile_missing_failed_or_empty")

    qualified = bool(
        assembly
        and assembly.get("status") == "success"
        and assembly_text.strip()
        and instruction
        and instruction.get("status") == "success"
        and len(instructions) >= 8
        and extent is not None
        and extent >= 32
        and len(pseudo_facts) == 3
        and all(item["status"] == "success" and item["useful"] for item in pseudo_facts)
        and len(set(pseudo_hashes)) == 1
        and isinstance(batch_item, dict)
        and batch.get("status") == "success"
        and batch_item.get("status") == "ok"
        and isinstance(batch_pseudo, str)
        and bool(batch_pseudo.strip())
    )
    return {
        "address": address,
        "independent_extent_bytes": extent,
        "observed_interval_bytes": observed_extent,
        "extent_basis": extent_basis,
        "assembly": {
            "status": assembly.get("status") if assembly else "missing",
            "nonempty": bool(assembly_text.strip()),
            "bytes": len(assembly_text.encode()),
            "sha256": digest(assembly_text) if assembly_text else None,
            "error": bounded_error(assembly) if assembly else "missing",
        },
        "instructions": {
            "status": instruction.get("status") if instruction else "missing",
            "count": len(instructions),
            "error": bounded_error(instruction) if instruction else "missing",
        },
        "pseudocode": {
            "repeats": len(pseudo_facts),
            "lengths": [item["length"] for item in pseudo_facts],
            "sha256": pseudo_hashes,
            "repeats_match": len(set(pseudo_hashes)) <= 1 and len(pseudo_hashes) == len(pseudo_facts),
            "bad_instruction_or_halt": any(item["bad_instruction_or_halt"] for item in pseudo_facts),
            "trivial_return": any(item["trivial_return"] for item in pseudo_facts),
            "useful": all(item["useful"] for item in pseudo_facts),
        },
        "batch_decompile": {
            "status": batch.get("status") if batch else "missing",
            "item_status": batch_item.get("status") if isinstance(batch_item, dict) else "missing",
            "nonempty": bool(isinstance(batch_pseudo, str) and batch_pseudo.strip()),
            "error": bounded_error(batch) if batch else "missing",
        },
        "qualified_for_measurement": qualified,
        "qualification_reasons": qualification_reasons,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    plan = json.loads(args.plan.read_text())
    workflows = []
    for workflow in plan.get("workflows", []):
        calls, load_errors = calls_in(args.work_dir, workflow["name"])
        candidates = []
        for item in workflow.get("candidate_addresses", []):
            candidates.append(candidate_fact(calls, item))
        workflows.append({
            "workflow": workflow["name"],
            "rounds_observed": sorted({c.get("_round") for c in calls}),
            "receipt_load_errors": load_errors,
            "qualified_count": sum(1 for c in candidates if c["qualified_for_measurement"]),
            "degraded_count": sum(1 for c in candidates if not c["qualified_for_measurement"]),
            "candidates": candidates,
        })
    output = {
        "schema_version": 1,
        "plan_id": plan.get("plan_id"),
        "purpose": "Bounded qualification facts from local native preflight receipts.",
        "source_policy": "Counts, statuses, limits, hashes, addresses, and errors only; no assembly, pseudocode, strings, or target source.",
        "extent_policy": "Adjacent known-start distances and function-start metadata are retained as planning intervals only; they do not qualify a function boundary without an independent end-boundary oracle.",
        "workflows": workflows,
    }
    args.output.write_text(json.dumps(output, indent=2) + "\n")


if __name__ == "__main__":
    main()
