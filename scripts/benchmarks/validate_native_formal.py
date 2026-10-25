#!/usr/bin/env python3
"""Validate a completed native-function benchmark lane with bounded facts."""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path
from typing import Any

EXPECTED_WORKFLOWS = (
    "figma-framework-native-functions-supplement",
    "openunity-native-functions-supplement",
    "zed-native-functions-supplement",
)
EXPECTED_ROUNDS = ("001", "002", "003", "004", "005")
EXPECTED_CANDIDATES = 5
EXPECTED_PSEUDOCODE_REPEATS = 3
EXPECTED_READ_BYTES = 256


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def structured_response(call: dict[str, Any] | None) -> dict[str, Any] | None:
    result = call.get("response", {}).get("result", {}).get("structuredContent") if call else None
    return result if isinstance(result, dict) else None


def load_workflow_receipts(
    work_dir: Path,
    workflow: str,
) -> tuple[dict[str, list[dict[str, Any]]], list[dict[str, str]]]:
    rounds: dict[str, list[dict[str, Any]]] = {}
    errors: list[dict[str, str]] = []
    for directory in sorted(work_dir.glob(f"{workflow}-round-*")):
        round_id = directory.name.rsplit("-round-", 1)[-1]
        calls: list[dict[str, Any]] = []
        for path in sorted(directory.glob("call-*.json")):
            try:
                call = json.loads(path.read_text())
            except OSError as exc:
                errors.append({"file": str(path), "error": type(exc).__name__})
                continue
            except json.JSONDecodeError:
                errors.append({"file": str(path), "error": "JSONDecodeError"})
                continue
            if not isinstance(call, dict):
                errors.append({"file": str(path), "error": "JSON_root_not_object"})
                continue
            calls.append(call)
        rounds[round_id] = calls
    return rounds, errors


def matching_calls(calls: list[dict[str, Any]], name: str, address: str | None = None) -> list[dict[str, Any]]:
    matches = []
    for call in calls:
        params = call.get("request", {}).get("params", {})
        if params.get("name") != name:
            continue
        if address is None:
            matches.append(call)
            continue
        arguments = params.get("arguments", {})
        if arguments.get("address") == address or arguments.get("procedure") == address:
            matches.append(call)
    return matches


def target_subject(calls_by_round: dict[str, list[dict[str, Any]]]) -> tuple[Path | None, str | None]:
    target_path: Path | None = None
    evidence_digest: str | None = None
    for calls in calls_by_round.values():
        for call in calls:
            result = structured_response(call)
            subject = result.get("subject") if result else None
            if not isinstance(subject, dict):
                continue
            local_path = subject.get("local_path")
            if target_path is None and isinstance(local_path, str):
                target_path = Path(local_path)
            digest = subject.get("digest")
            if evidence_digest is None and isinstance(digest, dict) and isinstance(digest.get("sha256"), str):
                evidence_digest = digest["sha256"]
    return target_path, evidence_digest


def macho_file_ranges(path: Path) -> list[tuple[int, int, int]]:
    with path.open("rb") as stream:
        header = stream.read(32)
        if len(header) < 32 or struct.unpack_from("<I", header)[0] != 0xFEEDFACF:
            return []
        command_count = struct.unpack_from("<I", header, 16)[0]
        ranges: list[tuple[int, int, int]] = []
        for _ in range(command_count):
            command_header = stream.read(8)
            if len(command_header) < 8:
                break
            command, command_size = struct.unpack("<II", command_header)
            if command_size < 8:
                break
            payload = stream.read(command_size - 8)
            if len(payload) != command_size - 8:
                break
            if command == 0x19 and command_size >= 72:
                _, vmaddr, _, file_offset, file_size, _, _, _, _ = struct.unpack_from(
                    "<16sQQQQiiII", payload
                )
                if file_size:
                    ranges.append((vmaddr, vmaddr + file_size, file_offset))
        return ranges


def read_file_slice(path: Path, offset: int, length: int) -> bytes:
    with path.open("rb") as stream:
        stream.seek(offset)
        return stream.read(length)


def pseudo_fact(call: dict[str, Any] | None) -> dict[str, Any]:
    result = structured_response(call)
    value = result.get("normalized_result") if result else None
    if isinstance(value, str):
        text = value
    elif isinstance(value, dict) and isinstance(value.get("pseudocode"), str):
        text = value["pseudocode"]
    else:
        text = ""
    encoded = text.encode()
    return {
        "status": call.get("status") if call else "missing",
        "nonempty": bool(text.strip()),
        "length": len(encoded),
        "sha256": sha256_bytes(encoded) if encoded else None,
    }


def read_bytes_fact(
    call: dict[str, Any] | None,
    target_path: Path | None,
    ranges: list[tuple[int, int, int]],
) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []
    result = structured_response(call)
    value = result.get("normalized_result") if result else None
    if not isinstance(value, dict):
        return (
            {"status": call.get("status") if call else "missing", "matched": None, "error": "missing_result"},
            ["read_bytes_result_missing"],
        )

    hex_value = value.get("bytes_hex")
    fact = {
        "status": call.get("status") if call else "missing",
        "requested_bytes": value.get("requested_bytes"),
        "returned_bytes": value.get("returned_bytes"),
        "complete": value.get("complete"),
        "provider_sha256": None,
        "matched": None,
        "file_offset": None,
        "error": None,
    }
    if call is None or call.get("status") != "success":
        errors.append("read_bytes_status_failed")
    if value.get("requested_bytes") != EXPECTED_READ_BYTES:
        errors.append("read_bytes_requested_length_unexpected")
    if value.get("returned_bytes") != EXPECTED_READ_BYTES:
        errors.append("read_bytes_returned_length_unexpected")
    if value.get("complete") is not True:
        errors.append("read_bytes_incomplete")
    if not isinstance(hex_value, str):
        fact["error"] = "bytes_hex_missing"
        errors.append("read_bytes_hex_missing")
        return fact, errors

    try:
        raw = bytes.fromhex(hex_value)
        fact["provider_sha256"] = sha256_bytes(raw)
        address = int(value["address"], 16)
    except (KeyError, TypeError, ValueError) as exc:
        fact["error"] = type(exc).__name__
        errors.append("read_bytes_payload_invalid")
        return fact, errors

    if target_path is None:
        fact["error"] = "target_file_missing"
        errors.append("read_bytes_target_file_missing")
        return fact, errors
    for start, end, file_offset in ranges:
        if start <= address < end and address + len(raw) <= end:
            offset = file_offset + address - start
            expected = read_file_slice(target_path, offset, len(raw))
            fact["file_offset"] = offset
            fact["file_sha256"] = sha256_bytes(expected)
            fact["matched"] = expected == raw
            if fact["matched"] is not True:
                errors.append("read_bytes_file_mismatch")
            return fact, errors
    fact["error"] = "address_not_mapped_to_file_backed_segment"
    errors.append("read_bytes_address_unmapped")
    return fact, errors


def validate_candidate_round(
    calls: list[dict[str, Any]],
    address: str,
    target_path: Path | None,
    ranges: list[tuple[int, int, int]],
) -> dict[str, Any]:
    assembly_calls = matching_calls(calls, "procedure_assembly", address)
    instruction_calls = matching_calls(calls, "read_function_instructions", address)
    pseudo_calls = matching_calls(calls, "procedure_pseudo_code", address)
    batch_calls = matching_calls(calls, "batch_decompile")
    read_calls = matching_calls(calls, "read_bytes", address)
    errors: list[str] = []

    if len(assembly_calls) != 1:
        errors.append(f"procedure_assembly_calls={len(assembly_calls)}")
    assembly = assembly_calls[0] if assembly_calls else None
    assembly_result = structured_response(assembly)
    assembly_value = assembly_result.get("normalized_result") if assembly_result else None
    if not assembly or assembly.get("status") != "success" or not isinstance(assembly_value, str) or not assembly_value.strip():
        errors.append("assembly_failed_or_empty")

    if len(instruction_calls) != 1:
        errors.append(f"read_function_instructions_calls={len(instruction_calls)}")
    instructions = instruction_calls[0] if instruction_calls else None
    instruction_result = structured_response(instructions)
    instruction_value = instruction_result.get("normalized_result") if instruction_result else None
    instruction_list = instruction_value.get("instructions") if isinstance(instruction_value, dict) else None
    if not isinstance(instruction_list, list) or not instruction_list:
        errors.append("instructions_missing_or_empty")
    if not instructions or instructions.get("status") != "success":
        errors.append("instructions_failed")

    pseudo = [pseudo_fact(call) for call in pseudo_calls]
    if len(pseudo_calls) != EXPECTED_PSEUDOCODE_REPEATS:
        errors.append(f"procedure_pseudo_code_calls={len(pseudo_calls)}")
    if not all(item["status"] == "success" and item["nonempty"] and item["sha256"] for item in pseudo):
        errors.append("pseudocode_status_content_or_hash_invalid")
    if len(pseudo) == EXPECTED_PSEUDOCODE_REPEATS and len({item["sha256"] for item in pseudo}) != 1:
        errors.append("pseudocode_repeat_hashes_differ")

    if len(batch_calls) != 1:
        errors.append(f"batch_decompile_calls={len(batch_calls)}")
    batch = batch_calls[0] if batch_calls else None
    batch_result = structured_response(batch)
    batch_items = batch_result.get("normalized_result", {}).get("items", []) if batch_result else []
    batch_item = next((item for item in batch_items if item.get("address") == address), None) if isinstance(batch_items, list) else None
    if not batch or batch.get("status") != "success" or not isinstance(batch_item, dict) or batch_item.get("status") != "ok":
        errors.append("batch_item_missing_or_failed")
    elif not isinstance(batch_item.get("pseudocode"), str) or not batch_item["pseudocode"].strip():
        errors.append("batch_pseudocode_empty")

    if len(read_calls) != 1:
        errors.append(f"read_bytes_calls={len(read_calls)}")
    read_fact, read_errors = read_bytes_fact(read_calls[0] if read_calls else None, target_path, ranges)
    errors.extend(read_errors)

    return {
        "assembly_status": assembly.get("status") if assembly else "missing",
        "instructions_status": instructions.get("status") if instructions else "missing",
        "instruction_count": len(instruction_list) if isinstance(instruction_list, list) else 0,
        "pseudocode": pseudo,
        "pseudocode_repeats_match": len(pseudo) == EXPECTED_PSEUDOCODE_REPEATS and len({item["sha256"] for item in pseudo}) == 1 and all(item["sha256"] for item in pseudo),
        "batch_status": batch.get("status") if batch else "missing",
        "batch_item_status": batch_item.get("status") if isinstance(batch_item, dict) else "missing",
        "read_bytes": read_fact,
        "validation_errors": errors,
    }


def candidate_addresses(rounds: dict[str, list[dict[str, Any]]]) -> list[str]:
    addresses = set()
    for calls in rounds.values():
        for call in matching_calls(calls, "read_bytes"):
            address = call.get("request", {}).get("params", {}).get("arguments", {}).get("address")
            if isinstance(address, str):
                addresses.add(address)
    return sorted(addresses)


def validate_workflow(work_dir: Path, workflow: str) -> dict[str, Any]:
    rounds, load_errors = load_workflow_receipts(work_dir, workflow)
    target_path, evidence_digest = target_subject(rounds)
    target_exists = target_path is not None and target_path.exists()
    ranges = macho_file_ranges(target_path) if target_exists else []
    file_digest = sha256_file(target_path) if target_exists else None
    errors: list[Any] = list(load_errors)

    if target_path is None:
        errors.append({"error": "target_path_missing"})
    elif not target_exists:
        errors.append({"error": "target_path_unavailable", "path": str(target_path)})
    if len(rounds) != len(EXPECTED_ROUNDS):
        errors.append({"error": "round_count", "observed": len(rounds), "expected": len(EXPECTED_ROUNDS)})
    if set(rounds) != set(EXPECTED_ROUNDS):
        errors.append({"error": "round_ids", "observed": sorted(rounds), "expected": list(EXPECTED_ROUNDS)})

    addresses = candidate_addresses(rounds)
    if len(addresses) != EXPECTED_CANDIDATES:
        errors.append({"error": "candidate_count", "observed": len(addresses), "expected": EXPECTED_CANDIDATES})

    candidates = []
    for address in addresses:
        per_round: dict[str, dict[str, Any]] = {}
        for round_id, calls in sorted(rounds.items()):
            fact = validate_candidate_round(calls, address, target_path, ranges)
            per_round[round_id] = fact
            if fact["validation_errors"]:
                errors.append({"error": "candidate_round", "round": round_id, "address": address, "details": fact["validation_errors"]})
        if len(per_round) != len(EXPECTED_ROUNDS):
            errors.append({"error": "candidate_round_count", "address": address, "observed": len(per_round), "expected": len(EXPECTED_ROUNDS)})

        pseudo_round_hashes = [tuple(item["sha256"] for item in fact["pseudocode"]) for fact in per_round.values()]
        instruction_counts = [fact["instruction_count"] for fact in per_round.values()]
        read_hashes = [fact["read_bytes"].get("provider_sha256") for fact in per_round.values()]
        pseudo_stable = len(pseudo_round_hashes) == len(EXPECTED_ROUNDS) and len(set(pseudo_round_hashes)) == 1 and all(all(item) for item in pseudo_round_hashes)
        instructions_stable = len(instruction_counts) == len(EXPECTED_ROUNDS) and len(set(instruction_counts)) == 1
        bytes_stable = len(read_hashes) == len(EXPECTED_ROUNDS) and len(set(read_hashes)) == 1 and all(read_hashes)
        if not pseudo_stable:
            errors.append({"error": "cross_round_pseudocode_instability", "address": address})
        if not instructions_stable:
            errors.append({"error": "cross_round_instruction_count_instability", "address": address})
        if not bytes_stable:
            errors.append({"error": "cross_round_read_bytes_instability", "address": address})
        candidates.append({
            "address": address,
            "rounds": per_round,
            "cross_round_pseudocode_hashes_match": pseudo_stable,
            "cross_round_instruction_counts_match": instructions_stable,
            "cross_round_read_bytes_match": bytes_stable,
        })

    digest_matches = bool(file_digest and evidence_digest == file_digest)
    if not digest_matches:
        errors.append({"error": "subject_digest_mismatch_or_unavailable"})
    return {
        "workflow": workflow,
        "round_count": len(rounds),
        "target_path": str(target_path) if target_path else None,
        "target_sha256": file_digest,
        "evidence_subject_sha256": evidence_digest,
        "subject_digest_matches_file": digest_matches,
        "mach_o_file_backed_ranges_observed": len(ranges),
        "validation_errors": errors,
        "candidates": candidates,
    }


def build_report(work_dir: Path) -> tuple[dict[str, Any], bool]:
    discovered = sorted({path.name.rsplit("-round-", 1)[0] for path in work_dir.glob("*-round-*")})
    workflows = [validate_workflow(work_dir, name) for name in EXPECTED_WORKFLOWS]
    unexpected = sorted(set(discovered) - set(EXPECTED_WORKFLOWS))
    global_errors: list[Any] = []
    if unexpected:
        global_errors.append({"error": "unexpected_workflows", "workflows": unexpected})
    if not discovered:
        global_errors.append({"error": "no_workflow_directories"})
    has_errors = bool(global_errors) or any(workflow["validation_errors"] for workflow in workflows)
    return {
        "schema_version": 1,
        "purpose": "Bounded validation facts from completed native formal receipts.",
        "source_policy": "Statuses, counts, repeat hashes, byte counts/digests, file mapping and bounded errors only; no assembly, pseudocode, strings, or target source.",
        "extent_policy": "No independent function extent or semantic correctness claim; adjacent-start intervals remain planning evidence only.",
        "expected_contract": {
            "workflows": list(EXPECTED_WORKFLOWS),
            "rounds_per_workflow": list(EXPECTED_ROUNDS),
            "candidates_per_workflow": EXPECTED_CANDIDATES,
            "pseudocode_repeats_per_candidate_round": EXPECTED_PSEUDOCODE_REPEATS,
            "read_bytes_per_candidate_round": EXPECTED_READ_BYTES,
        },
        "validation_errors": global_errors,
        "workflows": workflows,
    }, has_errors


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report, has_errors = build_report(args.work_dir)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    if has_errors:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
