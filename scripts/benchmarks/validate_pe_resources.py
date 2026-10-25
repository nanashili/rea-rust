#!/usr/bin/env python3
"""Validate bounded PE-resource facts and direct payload/file digests."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

EXPECTED_ROUNDS = ("001", "002", "003", "004", "005")
EXPECTED_WORKFLOW = "unity-pe-resources"
EXPECTED_RESOURCES = 1
EXPECTED_EXAMINED_ENTRIES = 3
ROUND_NAME = re.compile(r"^(?P<workflow>.+)-round-(?P<round>\d+)$")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def is_nonnegative_integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def file_identity(path: Path) -> dict[str, Any] | None:
    try:
        size = path.stat().st_size
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except (OSError, ValueError):
        return None
    return {"path": str(path), "bytes": size, "sha256": digest.hexdigest()}


def structured_content(call: dict[str, Any]) -> dict[str, Any] | None:
    response = call.get("response")
    result = response.get("result") if isinstance(response, dict) else None
    value = result.get("structuredContent") if isinstance(result, dict) else None
    return value if isinstance(value, dict) else None


def call_name(call: dict[str, Any]) -> str | None:
    request = call.get("request")
    params = request.get("params") if isinstance(request, dict) else None
    name = params.get("name") if isinstance(params, dict) else None
    return name if isinstance(name, str) else None


def load_round(round_dir: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    calls: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    call_files = sorted(round_dir.glob("call-*.json"))
    if not call_files:
        errors.append({"directory": str(round_dir), "error": "no_call_receipts"})

    for path in call_files:
        try:
            value = json.loads(path.read_text())
        except OSError as exc:
            errors.append({"file": str(path), "error": type(exc).__name__})
            continue
        except json.JSONDecodeError:
            errors.append({"file": str(path), "error": "JSONDecodeError"})
            continue
        if not isinstance(value, dict):
            errors.append({"file": str(path), "error": "JSON_root_not_object"})
            continue
        calls.append(value)
    return calls, errors


def parse_result(round_id: str, calls: list[dict[str, Any]]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    errors: list[dict[str, Any]] = []
    operation_calls = [call for call in calls if call_name(call) == "inspect_pe_resources"]
    if len(operation_calls) != 1:
        errors.append({"error": "inspect_pe_resources_call_count", "observed": len(operation_calls)})

    call = operation_calls[0] if len(operation_calls) == 1 else None
    status = call.get("status") if call else "missing"
    if status != "success":
        errors.append({"error": "inspect_pe_resources_status", "status": status})

    result = structured_content(call) if call else None
    normalized = result.get("normalized_result") if result else None
    subject = result.get("subject") if result else None
    artifact = normalized.get("artifact") if isinstance(normalized, dict) else None
    coverage = normalized.get("coverage") if isinstance(normalized, dict) else None
    resources = normalized.get("resources") if isinstance(normalized, dict) else None

    if not isinstance(normalized, dict):
        errors.append({"error": "normalized_result_missing"})
        normalized = {}
    if not isinstance(artifact, dict):
        errors.append({"error": "artifact_shape_invalid"})
        artifact = {}
    if not isinstance(coverage, dict):
        errors.append({"error": "coverage_shape_invalid"})
        coverage = {}
    if not isinstance(resources, list):
        errors.append({"error": "resources_shape_invalid"})
        resources = []

    return {
        "round": round_id,
        "status": status,
        "normalized": normalized,
        "subject": subject if isinstance(subject, dict) else {},
        "artifact": artifact,
        "coverage": coverage,
        "resources": resources,
    }, errors


def reported_target_path(parsed: dict[str, Any]) -> str | None:
    subject_path = parsed["subject"].get("local_path")
    artifact_path = parsed["artifact"].get("path")
    if isinstance(subject_path, str):
        return subject_path
    if isinstance(artifact_path, str):
        return artifact_path
    return None


def validate_artifact_identity(
    parsed: dict[str, Any],
    identity: dict[str, Any] | None,
    expected_path: str | None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    artifact = parsed["artifact"]
    subject = parsed["subject"]
    errors: list[dict[str, Any]] = []
    artifact_path = artifact.get("path")
    artifact_digest = artifact.get("sha256")
    artifact_bytes = artifact.get("bytes")
    subject_digest = subject.get("digest", {}).get("sha256") if isinstance(subject.get("digest"), dict) else None

    if not isinstance(artifact_path, str):
        errors.append({"error": "artifact_path_invalid"})
    elif expected_path is not None and artifact_path != expected_path:
        errors.append({"error": "artifact_path_mismatch", "observed": artifact_path, "expected": expected_path})
    if not isinstance(artifact_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", artifact_digest):
        errors.append({"error": "artifact_sha256_invalid"})
    if not isinstance(artifact_bytes, int) or isinstance(artifact_bytes, bool) or artifact_bytes < 0:
        errors.append({"error": "artifact_bytes_invalid"})

    if identity is None:
        errors.append({"error": "artifact_file_unavailable"})
    else:
        if artifact_digest != identity["sha256"]:
            errors.append({"error": "artifact_digest_mismatch"})
        if artifact_bytes != identity["bytes"]:
            errors.append({"error": "artifact_size_mismatch"})
        if subject_digest != identity["sha256"]:
            errors.append({"error": "subject_digest_mismatch"})

    return {"bytes": artifact_bytes, "sha256": artifact_digest}, errors


def validate_coverage(parsed: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    normalized = parsed["normalized"]
    coverage = parsed["coverage"]
    resources = parsed["resources"]
    errors: list[dict[str, Any]] = []
    format_name = normalized.get("format")
    if format_name not in {"pe32", "pe32plus"}:
        errors.append({"error": "unexpected_format", "format": format_name})
    if coverage.get("status") != "complete":
        errors.append({"error": "coverage_status", "status": coverage.get("status")})
    if coverage.get("examined_entries") != EXPECTED_EXAMINED_ENTRIES:
        errors.append({"error": "examined_entries", "observed": coverage.get("examined_entries")})
    if coverage.get("resources") != EXPECTED_RESOURCES or len(resources) != EXPECTED_RESOURCES:
        errors.append({"error": "resource_count", "coverage": coverage.get("resources"), "observed": len(resources)})

    limitations = normalized.get("limitations")
    if not isinstance(limitations, list) or not all(isinstance(item, str) for item in limitations):
        errors.append({"error": "limitations_shape_invalid"})
        limitations = (
            [item for item in limitations or [] if isinstance(item, str)]
            if isinstance(limitations, list)
            else []
        )
    malformed_version = any("RT_VERSION" in item and "malformed" in item.lower() for item in limitations)
    if not malformed_version:
        errors.append({"error": "missing_malformed_rt_version_limitation"})

    return {
        "format": format_name,
        "coverage": {
            "status": coverage.get("status"),
            "examined_entries": coverage.get("examined_entries"),
            "resources": coverage.get("resources"),
        },
        "resource_count": len(resources),
        "limitations": limitations,
        "malformed_rt_version": malformed_version,
    }, errors


def validate_resource_payloads(
    parsed: dict[str, Any],
    target_path: Path | None,
    file_bytes: int | None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    errors: list[dict[str, Any]] = []
    payload_facts: list[dict[str, Any]] = []
    for index, resource in enumerate(parsed["resources"]):
        payload = resource.get("payload") if isinstance(resource, dict) else None
        location = payload.get("location") if isinstance(payload, dict) else None
        if not isinstance(payload, dict) or not isinstance(location, dict):
            errors.append({"error": "resource_payload_location_missing", "resource": index})
            continue

        offset = location.get("offset")
        length = location.get("bytes")
        provider_digest = payload.get("sha256")
        fact: dict[str, Any] = {
            "offset": offset,
            "bytes": length,
            "provider_sha256": provider_digest,
            "matched": None,
        }
        payload_facts.append(fact)
        if not is_nonnegative_integer(offset) or not is_nonnegative_integer(length):
            errors.append({"error": "resource_payload_location_invalid", "resource": index})
            continue
        if file_bytes is None or offset > file_bytes or length > file_bytes - offset:
            errors.append({"error": "resource_payload_location_out_of_bounds", "resource": index})
            continue
        if not isinstance(provider_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", provider_digest):
            errors.append({"error": "resource_payload_sha256_invalid", "resource": index})
            continue
        if target_path is None:
            errors.append({"error": "resource_payload_file_unavailable", "resource": index})
            continue

        try:
            with target_path.open("rb") as stream:
                stream.seek(offset)
                actual = stream.read(length)
        except OSError as exc:
            errors.append({"error": "resource_payload_read_failed", "resource": index, "detail": type(exc).__name__})
            continue
        if len(actual) != length:
            errors.append(
                {
                    "error": "resource_payload_incomplete_read",
                    "resource": index,
                    "observed": len(actual),
                    "expected": length,
                }
            )
            continue

        file_digest = sha256_bytes(actual)
        fact["file_sha256"] = file_digest
        fact["matched"] = file_digest == provider_digest
        if fact["matched"] is not True:
            errors.append({"error": "resource_payload_digest_mismatch", "resource": index, "offset": offset})
    return payload_facts, errors


def validate_round(
    round_id: str,
    calls: list[dict[str, Any]],
    identity: dict[str, Any] | None,
    expected_path: str | None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    parsed, errors = parse_result(round_id, calls)
    artifact_fact, artifact_errors = validate_artifact_identity(parsed, identity, expected_path)
    coverage_fact, coverage_errors = validate_coverage(parsed)
    target_path = Path(expected_path) if expected_path is not None and identity is not None else None
    file_bytes = identity.get("bytes") if identity is not None else None
    payload_facts, payload_errors = validate_resource_payloads(
        parsed,
        target_path,
        file_bytes if is_nonnegative_integer(file_bytes) else None,
    )
    errors.extend(artifact_errors)
    errors.extend(coverage_errors)
    errors.extend(payload_errors)
    return {
        "round": round_id,
        "status": parsed["status"],
        **coverage_fact,
        "artifact": artifact_fact,
        "payloads": payload_facts,
        "validation_errors": errors,
    }, errors


def discover_rounds(work_dir: Path) -> tuple[dict[str, list[Path]], list[dict[str, Any]]]:
    grouped: dict[str, list[Path]] = {}
    errors: list[dict[str, Any]] = []
    if not work_dir.is_dir():
        return grouped, [{"error": "work_directory_unavailable", "path": str(work_dir)}]

    for child in sorted(work_dir.iterdir()):
        if not child.is_dir():
            continue
        match = ROUND_NAME.match(child.name)
        if match is None:
            errors.append({"error": "unexpected_workflow_directory", "directory": str(child)})
            continue
        workflow = match.group("workflow")
        if workflow != EXPECTED_WORKFLOW:
            errors.append({"error": "unexpected_workflow", "workflow": workflow, "directory": str(child)})
            continue
        grouped.setdefault(match.group("round"), []).append(child)

    for round_id, directories in grouped.items():
        if len(directories) > 1:
            errors.append(
                {
                    "error": "duplicate_round",
                    "round": round_id,
                    "directories": [str(item) for item in directories],
                }
            )
    return grouped, errors


def load_rounds(
    grouped: dict[str, list[Path]],
) -> dict[str, tuple[list[dict[str, Any]], list[dict[str, Any]]]]:
    loaded: dict[str, tuple[list[dict[str, Any]], list[dict[str, Any]]]] = {}
    for round_id in EXPECTED_ROUNDS:
        directories = grouped.get(round_id, [])
        if len(directories) != 1:
            continue
        loaded[round_id] = load_round(directories[0])
    return loaded


def select_target_identity(
    loaded: dict[str, tuple[list[dict[str, Any]], list[dict[str, Any]]]],
    errors: list[dict[str, Any]],
) -> tuple[str | None, dict[str, Any] | None]:
    expected_path: str | None = None
    for round_id, (calls, _load_errors) in loaded.items():
        parsed, _parse_errors = parse_result(round_id, calls)
        candidate = reported_target_path(parsed)
        if candidate is None:
            continue
        if expected_path is None:
            expected_path = candidate
            continue
        if candidate != expected_path:
            errors.append(
                {
                    "round": round_id,
                    "error": "target_path_changed_across_rounds",
                    "observed": candidate,
                    "expected": expected_path,
                }
            )

    if expected_path is None:
        errors.append({"error": "target_path_missing"})
        return None, None

    identity = file_identity(Path(expected_path))
    if identity is None:
        errors.append({"error": "artifact_file_unavailable", "path": expected_path})
    return expected_path, identity


def validate_loaded_rounds(
    loaded: dict[str, tuple[list[dict[str, Any]], list[dict[str, Any]]]],
    identity: dict[str, Any] | None,
    expected_path: str | None,
    errors: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    rounds: list[dict[str, Any]] = []
    for round_id in EXPECTED_ROUNDS:
        if round_id not in loaded:
            continue
        calls, load_errors = loaded[round_id]
        fact, round_errors = validate_round(round_id, calls, identity, expected_path)
        all_round_errors = load_errors + round_errors
        fact["validation_errors"] = all_round_errors
        errors.extend({"round": round_id, **item} for item in all_round_errors)
        rounds.append(fact)
    return rounds


def build_report(work_dir: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    grouped, errors = discover_rounds(work_dir)
    observed_ids = sorted(grouped)
    if observed_ids != list(EXPECTED_ROUNDS):
        errors.append({"error": "round_ids", "observed": observed_ids, "expected": list(EXPECTED_ROUNDS)})

    loaded = load_rounds(grouped)
    expected_path, identity = select_target_identity(loaded, errors)
    rounds = validate_loaded_rounds(loaded, identity, expected_path, errors)

    report = {
        "schema_version": 1,
        "purpose": "Bounded PE-resource validation facts from completed receipts.",
        "source_policy": (
            "Counts, format, artifact/resource sizes, digests, coverage, limitations, "
            "and direct byte agreement only; no resource payload text or target source."
        ),
        "limitations": [
            "RT_VERSION was reported malformed and version metadata remains unknown.",
            "This report does not claim fully decoded version resources or semantic correctness.",
        ],
        "workflow": EXPECTED_WORKFLOW,
        "target_path": expected_path,
        "target_sha256": identity["sha256"] if identity else None,
        "validation_errors": errors,
        "rounds": rounds,
    }
    return report, errors


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report, errors = build_report(args.work_dir)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    if errors:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
