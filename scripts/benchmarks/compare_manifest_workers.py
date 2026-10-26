#!/usr/bin/env python3
"""Compare two REA JavaScript workers over a source manifest.

Each binary receives identical source bytes, path, and file metadata. The
receipt keeps protocol and semantic field hashes only; source text and frames
are never retained. Partial semantic coverage can be an intentional comparable
result for adversarial fixtures; completion flags are reported separately from
semantic equality and must not be read as a claim of full analysis.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

from compare_js_workers import build_worker_request, run_worker


def file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def compare_result(baseline: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    baseline_frames = baseline.get("frames", {})
    candidate_frames = candidate.get("frames", {})
    baseline_hashes = baseline_frames.get("semantic_hashes", {})
    candidate_hashes = candidate_frames.get("semantic_hashes", {})
    required_fields = (
        "static_analysis",
        "semantic_ir",
        "semantic_projection",
        "semantic_metadata",
        "semantic_failure",
    )
    completion_fields = (
        "worker_completed",
        "semantic_coverage_complete",
        "projection_complete",
    )
    differences = [
        field
        for field in required_fields
        if baseline_hashes.get(field) != candidate_hashes.get(field)
    ]
    if baseline.get("status") != candidate.get("status"):
        differences.append("worker-status")
    for field in completion_fields:
        if baseline.get(field) != candidate.get(field):
            differences.append(f"completion-{field}")
    baseline_failures = []
    candidate_failures = []
    for label, result, failures in (
        ("baseline", baseline, baseline_failures),
        ("candidate", candidate, candidate_failures),
    ):
        frames = result.get("frames", {})
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
        for field in required_fields:
            if field not in (baseline_hashes if label == "baseline" else candidate_hashes):
                failures.append(f"{label}:missing-{field}")
    return {
        "baseline": {
            "status": baseline.get("status"),
            "complete": baseline.get("complete"),
            "worker_completed": baseline.get("worker_completed"),
            "semantic_coverage_complete": baseline.get("semantic_coverage_complete"),
            "projection_complete": baseline.get("projection_complete"),
            "semantic_hashes": baseline_hashes,
        },
        "candidate": {
            "status": candidate.get("status"),
            "complete": candidate.get("complete"),
            "worker_completed": candidate.get("worker_completed"),
            "semantic_coverage_complete": candidate.get("semantic_coverage_complete"),
            "projection_complete": candidate.get("projection_complete"),
            "semantic_hashes": candidate_hashes,
        },
        "semantic_differences": differences,
        "failures": baseline_failures + candidate_failures,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-commit")
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit(f"refusing to overwrite existing receipt: {args.output}")

    entries = json.loads(args.manifest.read_text(encoding="utf-8"))
    if not isinstance(entries, list):
        raise SystemExit("manifest must contain an array")
    ids = [entry.get("id") for entry in entries if isinstance(entry, dict)]
    if (
        len(entries) != 17
        or len(ids) != 17
        or any(not isinstance(value, str) or not value for value in ids)
        or len(set(ids)) != 17
    ):
        raise SystemExit("manifest must contain 17 entries with unique non-empty ids")
    manifest_dir = args.manifest.parent
    manifest_hash = file_digest(args.manifest)
    results: list[dict[str, Any]] = []
    for entry in entries:
        source_path = manifest_dir / entry["file"]
        source = source_path.read_bytes()
        source_hash = hashlib.sha256(source).hexdigest()
        metadata = {
            "archive_sha256": manifest_hash,
            "sha256": source_hash,
            "bytes": len(source),
        }
        request = build_worker_request(source, entry["path"], metadata)
        baseline = run_worker(
            f"{entry['id']}#baseline", args.baseline, request, compare_semantic_fields=True
        )
        candidate = run_worker(
            f"{entry['id']}#candidate", args.candidate, request, compare_semantic_fields=True
        )
        results.append(
            {
                "id": entry["id"],
                "path": entry["path"],
                "source_sha256": source_hash,
                "comparison": compare_result(baseline, candidate),
            }
        )

    receipt = {
        "schema": "rea-js-worker-manifest-comparison-v1",
        "source_commit": args.source_commit,
        "manifest_sha256": manifest_hash,
        "script_sha256": file_digest(Path(__file__).resolve()),
        "runner_sha256": file_digest(
            Path(__file__).with_name("compare_js_workers.py").resolve()
        ),
        "baseline_sha256": file_digest(args.baseline),
        "candidate_sha256": file_digest(args.candidate),
        "case_count": len(results),
        "results": results,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    differences = sum(
        bool(
            result["comparison"]["semantic_differences"]
            or result["comparison"]["failures"]
        )
        for result in results
    )
    print(json.dumps({"cases": len(results), "semantic_differences": differences}))
    return 1 if differences else 0


if __name__ == "__main__":
    sys.exit(main())
