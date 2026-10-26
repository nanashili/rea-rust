#!/usr/bin/env python3
"""Compare semantic field hashes for a diagnostic reference and candidate worker.

The reference run uses extended Build29 diagnostic capture limits. The candidate
run uses production worker limits. This is an oracle check, not a benchmark:
results contain protocol metadata and hashes, while raw frames stay temporary.
Field parity may pass for two intentionally partial runs when their semantic
fields and completion flags match. The separate completion fields describe
whether either run actually reached full semantic coverage and projection.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from typing import Any, Iterator


REFERENCE_TIMEOUT_SECONDS = 90.0
REFERENCE_OUTPUT_BYTES = 192 * 1024 * 1024
CANDIDATE_TIMEOUT_SECONDS = 30.0
CANDIDATE_OUTPUT_BYTES = 64 * 1024 * 1024
MAX_HEAP_MB = 1024
NODE_BUDGET = 20_000
UNKNOWN_BUDGET = 20_000
SEMANTIC_FIELDS = (
    "static_analysis",
    "semantic_ir",
    "semantic_metadata",
    "semantic_projection",
    "semantic_failure",
)
NULL_HASH = hashlib.sha256(b"null").hexdigest()


@dataclass(frozen=True)
class RunProfile:
    name: str
    timeout_seconds: float
    output_cap_bytes: int
    purpose: str


REFERENCE_PROFILE = RunProfile(
    name="build29-diagnostic-reference",
    timeout_seconds=REFERENCE_TIMEOUT_SECONDS,
    output_cap_bytes=REFERENCE_OUTPUT_BYTES,
    purpose="Extended diagnostic capture; not a production result.",
)
CANDIDATE_PROFILE = RunProfile(
    name="candidate-production-limits",
    timeout_seconds=CANDIDATE_TIMEOUT_SECONDS,
    output_cap_bytes=CANDIDATE_OUTPUT_BYTES,
    purpose="Production worker limits.",
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_harness(path: Path) -> Any:
    spec = importlib.util.spec_from_file_location("rea_compare_js_workers", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load harness: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@contextmanager
def capture_profile(harness: Any, profile: RunProfile) -> Iterator[None]:
    saved = {
        "TIMEOUT_SECONDS": harness.TIMEOUT_SECONDS,
        "MAX_OUTPUT_BYTES": harness.MAX_OUTPUT_BYTES,
        "MAX_FRAME_BUFFER": harness.MAX_FRAME_BUFFER,
    }
    harness.TIMEOUT_SECONDS = profile.timeout_seconds
    harness.MAX_OUTPUT_BYTES = profile.output_cap_bytes
    harness.MAX_FRAME_BUFFER = profile.output_cap_bytes
    try:
        yield
    finally:
        for name, value in saved.items():
            setattr(harness, name, value)


def fixture_request(
    harness: Any,
    archive: Path,
    member: str,
) -> tuple[dict[str, Any], bytes]:
    selected_member, source, _, metadata = harness.read_asar_member(archive, member)
    request = harness.build_worker_request(source, selected_member, metadata)
    fixture = {
        "requested_member": member,
        "selected_member": selected_member,
        "archive": str(archive),
        "archive_sha256": metadata["archive_sha256"],
        "source_sha256": metadata["sha256"],
        "source_bytes": metadata["bytes"],
        "entry_offset": metadata["offset"],
    }
    return fixture, request


def run_profile(
    harness: Any,
    executable: Path,
    profile: RunProfile,
    fixture_name: str,
    request: bytes,
) -> dict[str, Any]:
    with capture_profile(harness, profile):
        result = harness.run_worker(
            f"{profile.name}:{fixture_name}",
            executable,
            request,
            compare_semantic_fields=True,
        )
    return {
        "profile": asdict(profile),
        "fixture": fixture_name,
        "executable": str(executable),
        "executable_sha256": sha256_file(executable),
        "result": result,
    }


def run_validity_failures(label: str, result: dict[str, Any]) -> list[str]:
    """Return lifecycle and protocol failures that invalidate field parity."""
    frames = result.get("frames")
    if not isinstance(frames, dict):
        frames = {}

    failures: list[str] = []
    if result.get("worker_completed") is not True:
        failures.append(f"{label}:worker-incomplete")
    if result.get("error") is not None:
        failures.append(f"{label}:runner-error")
    if result.get("cleanup_errors"):
        failures.append(f"{label}:cleanup-errors")
    if frames.get("protocol_invalid"):
        failures.append(f"{label}:protocol-invalid")
    if frames.get("semantic_failure"):
        failures.append(f"{label}:semantic-failure")
    return failures


def compare_runs(
    fixture_name: str,
    reference: dict[str, Any],
    candidate: dict[str, Any],
) -> dict[str, Any]:
    reference_result = reference["result"]
    candidate_result = candidate["result"]
    reference_frames = reference_result.get("frames", {})
    candidate_frames = candidate_result.get("frames", {})
    if not isinstance(reference_frames, dict):
        reference_frames = {}
    if not isinstance(candidate_frames, dict):
        candidate_frames = {}
    reference_hashes = reference_frames.get("semantic_hashes", {})
    candidate_hashes = candidate_frames.get("semantic_hashes", {})
    reference_validity_failures = run_validity_failures("reference", reference_result)
    candidate_validity_failures = run_validity_failures("candidate", candidate_result)
    validity_failures = reference_validity_failures + candidate_validity_failures

    hash_equality = {
        field: (
            reference_hashes.get(field) is not None
            and reference_hashes.get(field) == candidate_hashes.get(field)
        )
        for field in SEMANTIC_FIELDS
    }

    reference_worker_completed = bool(reference_result.get("worker_completed", False))
    candidate_worker_completed = bool(candidate_result.get("worker_completed", False))
    reference_semantic_coverage_complete = bool(
        reference_result.get("semantic_coverage_complete", False)
    )
    candidate_semantic_coverage_complete = bool(
        candidate_result.get("semantic_coverage_complete", False)
    )
    reference_projection_complete = bool(
        reference_result.get("projection_complete", False)
    )
    candidate_projection_complete = bool(
        candidate_result.get("projection_complete", False)
    )

    completion = {
        "reference_worker_completed": reference_worker_completed,
        "candidate_worker_completed": candidate_worker_completed,
        "reference_semantic_coverage_complete": reference_semantic_coverage_complete,
        "candidate_semantic_coverage_complete": candidate_semantic_coverage_complete,
        "reference_projection_complete": reference_projection_complete,
        "candidate_projection_complete": candidate_projection_complete,
        "reference_semantic_ir_is_null": reference_hashes.get("semantic_ir") == NULL_HASH,
        "candidate_semantic_ir_is_null": candidate_hashes.get("semantic_ir") == NULL_HASH,
        "reference_semantic_failure_is_null": reference_hashes.get("semantic_failure") == NULL_HASH,
        "candidate_semantic_failure_is_null": candidate_hashes.get("semantic_failure") == NULL_HASH,
    }

    completion.update(
        {
            "worker_completion_matches": reference_worker_completed
            == candidate_worker_completed,
            "semantic_coverage_completion_matches": reference_semantic_coverage_complete
            == candidate_semantic_coverage_complete,
            "projection_completion_matches": reference_projection_complete
            == candidate_projection_complete,
        }
    )
    completion["reference_full_analysis_complete"] = (
        reference_worker_completed
        and reference_semantic_coverage_complete
        and reference_projection_complete
        and completion["reference_semantic_failure_is_null"]
    )
    completion["candidate_full_analysis_complete"] = (
        candidate_worker_completed
        and candidate_semantic_coverage_complete
        and candidate_projection_complete
        and completion["candidate_semantic_failure_is_null"]
    )
    completion["full_analysis_complete"] = {
        "reference": completion["reference_full_analysis_complete"],
        "candidate": completion["candidate_full_analysis_complete"],
        "both": completion["reference_full_analysis_complete"]
        and completion["candidate_full_analysis_complete"],
    }
    completion["reference_valid"] = not reference_validity_failures
    completion["candidate_valid"] = not candidate_validity_failures

    field_parity_pass = (
        all(hash_equality.values())
        and not validity_failures
        and completion["reference_worker_completed"]
        and completion["candidate_worker_completed"]
        and completion["worker_completion_matches"]
        and completion["semantic_coverage_completion_matches"]
        and completion["projection_completion_matches"]
        and completion["reference_semantic_ir_is_null"]
        and completion["candidate_semantic_ir_is_null"]
        and completion["reference_semantic_failure_is_null"]
        and completion["candidate_semantic_failure_is_null"]
    )
    return {
        "fixture": fixture_name,
        "reference": reference,
        "candidate": candidate,
        "hash_equality": hash_equality,
        "completion": completion,
        "reference_validity_failures": reference_validity_failures,
        "candidate_validity_failures": candidate_validity_failures,
        "validity_failures": validity_failures,
        "field_parity_pass": field_parity_pass,
    }


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-executable", type=Path, required=True)
    parser.add_argument("--candidate-executable", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name("compare_js_workers.py"),
    )
    parser.add_argument(
        "--figma",
        type=Path,
        default=Path("/Applications/Figma.app/Contents/Resources/app.asar"),
    )
    parser.add_argument(
        "--postman",
        type=Path,
        default=Path("/Applications/Postman.app/Contents/Resources/app.asar"),
    )
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def build_receipt(args: argparse.Namespace, harness: Any) -> dict[str, Any]:
    fixtures = (
        ("figma-main", args.figma, "main.js"),
        ("postman-agent-worker", args.postman, "AgentWorker.js"),
    )
    receipt: dict[str, Any] = {
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "purpose": "Exact semantic-field transport oracle; diagnostic reference uses relaxed capture limits.",
        "timing_comparison": "Not comparable: reference and candidate use different diagnostic and production limits.",
        "hash_policy": {
            "canonical_json": "The imported harness hashes all five semantic fields canonically with ensure_ascii=true, sort_keys=true, and separators=(',', ':').",
            "fields": list(SEMANTIC_FIELDS),
            "null_hash": NULL_HASH,
            "raw_frames": "Never persisted; worker spools remain unlinked temporary files owned by run_worker.",
        },
        "limits": {
            "max_heap_mb": MAX_HEAP_MB,
            "node_budget": NODE_BUDGET,
            "unknown_budget": UNKNOWN_BUDGET,
            "reference": asdict(REFERENCE_PROFILE),
            "candidate": asdict(CANDIDATE_PROFILE),
        },
        "harness": {"path": str(args.harness), "sha256": sha256_file(args.harness)},
        "binaries": {
            "reference": {"path": str(args.reference_executable), "sha256": sha256_file(args.reference_executable)},
            "candidate": {"path": str(args.candidate_executable), "sha256": sha256_file(args.candidate_executable)},
        },
        "fixtures": [],
        "comparisons": [],
    }

    for fixture_name, archive, member in fixtures:
        metadata, request = fixture_request(harness, archive, member)
        receipt["fixtures"].append({"name": fixture_name, **metadata})
        reference = run_profile(harness, args.reference_executable, REFERENCE_PROFILE, fixture_name, request)
        candidate = run_profile(harness, args.candidate_executable, CANDIDATE_PROFILE, fixture_name, request)
        receipt["comparisons"].append(compare_runs(fixture_name, reference, candidate))

    receipt["field_parity_pass"] = bool(receipt["comparisons"]) and all(
        comparison["field_parity_pass"] for comparison in receipt["comparisons"]
    )
    receipt["full_analysis_complete"] = bool(receipt["comparisons"]) and all(
        comparison["completion"]["full_analysis_complete"]["both"]
        for comparison in receipt["comparisons"]
    )
    receipt["finished_utc"] = datetime.now(timezone.utc).isoformat()
    return receipt


def main() -> int:
    args = parse_arguments()
    harness = load_harness(args.harness)
    receipt = build_receipt(args, harness)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    return 0 if receipt["field_parity_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
