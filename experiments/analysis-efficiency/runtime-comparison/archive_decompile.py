#!/usr/bin/env python3
"""Archive compact, reproducible receipts for the Ghidra comparison.

The measured directory remains the owner of full protocol transcripts and
evidence.  This archiver records their immutable local paths and digests while
deliberately avoiding copies of binaries, inventories, or unselected pseudocode.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path
from typing import Any, Iterable


SCRIPT_DIR = Path(__file__).resolve().parent


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def artifact(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ValueError(f"missing receipt input: {path}")
    return {"path": str(path), "bytes": path.stat().st_size, "sha256": sha256(path)}


def optional_artifact(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {"path": str(path), "present": False}
    return {"present": True, **artifact(path)}


def canonical_digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read JSON receipt {path}: {exc}") from exc


def safe_child(root: Path, relative: str) -> Path:
    candidate = (root / relative).resolve()
    if not candidate.is_relative_to(root.resolve()):
        raise ValueError(f"manifest path escapes its root: {relative!r}")
    return candidate


def verify_manifest(root: Path, manifest: dict[str, Any], label: str) -> dict[str, Any]:
    entries = manifest.get("entries")
    if not isinstance(entries, list):
        raise ValueError(f"{label} has no file entries")

    for entry in entries:
        relative = entry.get("path")
        if not isinstance(relative, str):
            raise ValueError(f"{label} contains an invalid path")
        path = safe_child(root, relative)
        actual = artifact(path)
        if actual["bytes"] != entry.get("bytes") or actual["sha256"] != entry.get("sha256"):
            raise ValueError(f"{label} changed: {relative}")

    aggregate = manifest.get("aggregate_sha256")
    if aggregate and aggregate != canonical_digest(entries):
        raise ValueError(f"{label} aggregate digest changed")
    return {"root": str(root), "files": len(entries), "aggregate_sha256": aggregate}


def verify_harness(results: dict[str, Any]) -> dict[str, Any]:
    expected = results.get("harness_sha256")
    if not isinstance(expected, dict) or not expected:
        raise ValueError("results do not identify the benchmark harness")

    checked: dict[str, Any] = {}
    for name, expected_digest in sorted(expected.items()):
        path = Path(name)
        if not path.is_absolute():
            path = SCRIPT_DIR / name
        actual = artifact(path)
        if actual["sha256"] != expected_digest:
            raise ValueError(f"harness changed after measurement: {name}")
        checked[name] = actual
    return checked


def verify_binary(path: Path, expected: dict[str, Any], label: str) -> dict[str, Any]:
    actual = artifact(path)
    if actual["bytes"] != expected.get("bytes") or actual["sha256"] != expected.get("sha256"):
        raise ValueError(f"{label} digest changed: {path}")
    return actual


def verify_prepared(prepared: Path, results: dict[str, Any]) -> dict[str, Any]:
    provenance_path = prepared / "provenance.json"
    provenance = load_json(provenance_path)
    expected_provenance = results.get("prepared_provenance_sha256")
    actual_provenance = sha256(provenance_path)
    if expected_provenance != actual_provenance:
        raise ValueError("prepared provenance changed after measurement")

    build = provenance.get("build", {})
    executable = build.get("executable", {})
    verify_binary(Path(executable["path"]), executable, "worker")

    runtime = provenance.get("prepared_runtime", {}).get("binary", {})
    verify_binary(Path(runtime["path"]), runtime, "runtime")

    worker_path = prepared / "worker-source-manifest.json"
    worker_manifest = load_json(worker_path)
    worker_root = Path(worker_manifest["root"])
    worker_receipt = verify_manifest(worker_root, worker_manifest, "worker source")

    engine_path = prepared / "engine-identity.json"
    engine = load_json(engine_path)
    engine_root = Path(engine["source_root"])
    engine_entries = engine.get("manifest", [])
    verify_manifest(engine_root, {"entries": engine_entries}, "engine source")
    embedded = engine.get("embedded_languages", [])
    if engine.get("embedded_manifest_sha256") != canonical_digest(embedded):
        raise ValueError("embedded engine manifest changed")
    for item in embedded:
        verify_binary(safe_child(engine_root, item["path"]), item, "engine asset")

    ghidra = provenance.get("ghidra", {})
    ghidra_root = Path(ghidra["install_dir"])
    ghidra_entries = ghidra.get("manifest", [])
    for entry in ghidra_entries:
        verify_binary(safe_child(ghidra_root, entry["path"]), entry, "Ghidra input")
    launch_java = ghidra.get("launch_java") or ghidra.get("java", {}).get("launch_java")
    if launch_java:
        verify_binary(Path(launch_java["path"]), launch_java, "Java launch binary")
    if provenance.get("engine", {}).get("embedded_manifest_sha256") != engine.get(
        "embedded_manifest_sha256"
    ):
        raise ValueError("engine identity does not match prepared provenance")

    fixture_path = prepared / "fixtures" / "manifest.json"
    fixtures = load_json(fixture_path)
    if results.get("fixture_manifest_sha256") != sha256(fixture_path):
        raise ValueError("fixture manifest changed after measurement")
    for target in fixtures.get("targets", {}).values():
        binary = target.get("binary")
        if binary and isinstance(binary.get("path"), str):
            verify_binary(prepared / "fixtures" / binary["path"], binary, "fixture")
        for source in target.get("source_files", []):
            source_path = source.get("path")
            if isinstance(source_path, str):
                fixture_source = prepared / "fixtures" / source_path
                if not fixture_source.is_file() and isinstance(source.get("source"), str):
                    fixture_source = Path(source["source"])
                verify_binary(fixture_source, source, "fixture source")

    return {
        "provenance": artifact(provenance_path),
        "worker_source": worker_receipt,
        "worker_manifest": artifact(worker_path),
        "engine_identity": artifact(engine_path),
        "fixtures": artifact(fixture_path),
        "runtime_binary": runtime,
        "worker_binary": executable,
        "ghidra_manifest_sha256": ghidra.get("manifest_sha256"),
    }


def pseudocode_record(item: dict[str, Any], include_text: bool = False) -> dict[str, Any]:
    text = item.get("pseudocode")
    record = {
        key: item[key]
        for key in ("name", "selector", "phase", "status", "sha256", "wall_ms")
        if key in item
    } | {
        "nonempty": isinstance(text, str) and bool(text.strip()),
        "bytes": len(text.encode()) if isinstance(text, str) else None,
    }
    if "error" in item:
        record["error"] = item["error"]
    if include_text and isinstance(text, str):
        record["pseudocode"] = text
    return record


def quality_receipt(evidence: dict[str, Any]) -> dict[str, Any]:
    functions = evidence.get("functions", [])
    repeats = evidence.get("repeats", [])
    function_hashes = [item.get("sha256") for item in functions]
    repeat_hashes = [item.get("sha256") for item in repeats]
    return {
        "evidence_present": True,
        "function_count": len(functions),
        "repeat_count": len(repeats),
        "all_function_success": all(item.get("status") == "success" for item in functions),
        "all_repeat_success": all(item.get("status") == "success" for item in repeats),
        "all_pseudocode_nonempty": all(
            isinstance(item.get("pseudocode"), str) and item["pseudocode"].strip()
            for item in [*functions, *repeats]
        ),
        "function_hashes": function_hashes,
        "repeat_hashes": repeat_hashes,
        "repeat_matches_first": (
            bool(function_hashes)
            and isinstance(function_hashes[0], str)
            and bool(function_hashes[0])
            and len(repeat_hashes) == 8
            and all(isinstance(value, str) and value == function_hashes[0] for value in repeat_hashes)
        ),
    }


def compact_invocation(row: dict[str, Any]) -> dict[str, Any]:
    evidence_path = Path(row["evidence"]) if row.get("evidence") else None
    evidence = load_json(evidence_path) if evidence_path else {}
    quality = quality_receipt(evidence) if evidence else {
        "evidence_present": False,
        "function_count": 0,
        "repeat_count": 0,
    }
    if row.get("status") == "success" and not quality.get("all_pseudocode_nonempty"):
        raise ValueError(f"successful invocation has empty pseudocode: {evidence_path}")

    compact = {
        "identity": {key: row.get(key) for key in ("target", "sample", "lane", "provider")},
        "metrics": {
            key: value for key, value in row.items()
            if key not in {
                "target", "sample", "lane", "provider", "command", "functions", "repeats",
                "phases", "transcript", "evidence",
            }
        },
        "command": row.get("command"),
        "functions": [
            pseudocode_record(item, include_text=index < 3)
            for index, item in enumerate(evidence.get("functions", []))
        ],
        "repeats": [pseudocode_record(item) for item in evidence.get("repeats", [])],
        "quality": quality,
        "evidence": optional_artifact(evidence_path) if evidence_path else {"present": False},
    }
    return compact


def archive_transcripts(rows: Iterable[dict[str, Any]], output: Path) -> None:
    records = []
    for row in rows:
        identity = {key: row.get(key) for key in ("target", "sample", "lane")}
        transcript_value = row.get("transcript")
        if not transcript_value:
            records.append({"identity": identity, "kind": "transcript", "present": False})
            records.append({"identity": identity, "kind": "phases", "present": False})
            records.append({"identity": identity, "kind": "stderr", "present": False})
            continue
        transcript = Path(transcript_value)
        paths = {
            "transcript": transcript,
            "phases": transcript.with_name("phases.json"),
            "stderr": transcript.with_name("stderr.log"),
        }
        for kind, path in paths.items():
            records.append({"identity": identity, "kind": kind, **optional_artifact(path)})
    write_json(output / "transcript-manifest.json", records)


def load_measurements(measured_dirs: list[Path]) -> tuple[dict[str, Any], list[Path]]:
    if not measured_dirs:
        raise ValueError("at least one measured directory is required")

    documents = [load_json(directory / "results.json") for directory in measured_dirs]
    if any(document.get("qualification_only") for document in documents):
        raise ValueError("qualification results cannot be archived as measurements")
    rows = [row for document in documents for row in document.get("rows", [])]
    if not rows:
        raise ValueError("measured results contain no invocations")

    first = dict(documents[0])
    pin_fields = ("prepared_provenance_sha256", "fixture_manifest_sha256", "harness_sha256")
    for document in documents[1:]:
        for field in pin_fields:
            if document.get(field) != first.get(field):
                raise ValueError(f"measurement pin differs: {field}")
    starts = [document.get("started_at_utc") for document in documents if document.get("started_at_utc")]
    finishes = [document.get("finished_at_utc") for document in documents if document.get("finished_at_utc")]
    first["rows"] = rows
    first["comparisons"] = [
        comparison for document in documents for comparison in document.get("comparisons", [])
    ]
    first["measurement_inputs"] = [str(directory) for directory in measured_dirs]
    first["started_at_utc"] = min(starts) if starts else None
    first["finished_at_utc"] = max(finishes) if finishes else None
    first["summary"] = {
        target: summary
        for document in documents
        for target, summary in document.get("summary", {}).items()
    }
    first["measurement_sets"] = [
        {
            "path": str(directory),
            "schema": document.get("schema"),
            "started_at_utc": document.get("started_at_utc"),
            "finished_at_utc": document.get("finished_at_utc"),
            "summary": document.get("summary", {}),
            "rows": len(document.get("rows", [])),
            "token_method": document.get("token_method"),
        }
        for directory, document in zip(measured_dirs, documents)
    ]
    return first, [directory / "results.json" for directory in measured_dirs]


def archive_measurements(
    prepared: Path, measured_dirs: list[Path], output: Path
) -> dict[str, Any]:
    results, result_paths = load_measurements(measured_dirs)
    rows = results["rows"]

    harness = verify_harness(results)
    prepared_receipt = verify_prepared(prepared, results)
    write_json(output / "raw-results.json", results)
    write_json(output / "harness-verification.json", harness)
    write_json(output / "prepared-verification.json", prepared_receipt)
    archive_transcripts(rows, output)

    invocations = []
    for index, row in enumerate(rows, 1):
        receipt = compact_invocation(row)
        receipt["ordinal"] = index
        invocations.append(receipt)
    write_json(output / "invocations.json", invocations)
    return {
        "results": [artifact(path) for path in result_paths],
        "invocations": len(invocations),
    }


def archive(prepared: Path, measured_dirs: list[Path], output: Path) -> None:
    output.mkdir(parents=True, exist_ok=False)
    provenance = load_json(prepared / "provenance.json")
    results, _ = load_measurements(measured_dirs)
    prepared_receipt = verify_prepared(prepared, results)
    source_manifest = prepared / "worker-source-manifest.json"
    engine_identity = prepared / "engine-identity.json"
    fixtures = prepared / "fixtures" / "manifest.json"
    for source, destination in (
        (source_manifest, output / source_manifest.name),
        (engine_identity, output / engine_identity.name),
        (fixtures, output / "fixtures-manifest.json"),
    ):
        shutil.copy2(source, destination)

    measurement_receipt = archive_measurements(prepared, measured_dirs, output)
    write_json(output / "provenance.json", {
        "schema": "rea-ghidra-decompile-archive-v1",
        "prepared_provenance": provenance,
        "prepared_verification": prepared_receipt,
        "measurement": measurement_receipt,
        "full_transcripts": "Retained in the measured directory; transcript-manifest.json records path, bytes, and SHA-256.",
        "binary_policy": "No binaries are copied into this archive.",
        "failure_policy": "Observed failures are retained with available metrics and are not treated as equivalent outputs.",
    })


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--prepared", type=Path, required=True)
    parser.add_argument("--measured", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    archive(
        args.prepared.resolve(),
        [directory.resolve() for directory in args.measured],
        args.output.resolve(),
    )


if __name__ == "__main__":
    main()
