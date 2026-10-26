#!/usr/bin/env python3
"""Compare a frozen Rust SemanticIr run with pinned TypeScript JSONL outputs.

The Rust binary is run once per resolution mode. TypeScript outputs are read
only; this utility never invokes the TypeScript analyzer or replaces those
files. Reports contain bounded hashes and difference paths, rather than source
or full semantic records. Manifest worker comparisons may intentionally contain
partial semantic coverage; matching partial outputs are reported as parity,
while completion flags remain visible separately from semantic equality.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
from typing import Any


MODES = ("import", "require", "compiler-dependent")
MAX_DIFFERENCE_PATHS = 8


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
        "ascii"
    )


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_records(path: Path) -> dict[str, dict[str, Any]]:
    text = path.read_text(encoding="utf-8")
    decoded = json.loads(text) if path.suffix == ".json" else None
    if isinstance(decoded, list):
        values = decoded
    else:
        values = [
            json.loads(line)
            for line in text.splitlines()
            if line.strip()
        ]
    records: dict[str, dict[str, Any]] = {}
    for line_number, value in enumerate(values, 1):
        if not isinstance(value, dict) or not isinstance(value.get("id"), str):
            raise ValueError(f"{path}:{line_number} is not a record with a string id")
        record_id = value["id"]
        if record_id in records:
            raise ValueError(f"{path}:{line_number} repeats id {record_id!r}")
        records[record_id] = value
    return records


def remove_record_timing(record: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Exclude only the diagnostic wrapper's timer; preserve every IR field."""
    result = dict(record)
    if "micros" not in result:
        return result, []
    del result["micros"]
    return result, ["$.micros"]


def difference_paths(
    expected: Any,
    actual: Any,
    paths: list[str],
    path: str = "$",
) -> None:
    if len(paths) >= MAX_DIFFERENCE_PATHS or expected == actual:
        return
    if type(expected) is not type(actual):
        paths.append(path)
        return
    if isinstance(expected, list):
        if len(expected) != len(actual):
            paths.append(f"{path}.length")
            return
        for index, (left, right) in enumerate(zip(expected, actual)):
            difference_paths(left, right, paths, f"{path}[{index}]")
            if len(paths) >= MAX_DIFFERENCE_PATHS:
                break
        return
    if isinstance(expected, dict):
        for key in sorted(set(expected) | set(actual)):
            if key not in expected or key not in actual:
                paths.append(f"{path}.{key}")
            else:
                difference_paths(expected[key], actual[key], paths, f"{path}.{key}")
            if len(paths) >= MAX_DIFFERENCE_PATHS:
                break
        return
    paths.append(path)


def bounded_difference_paths(expected: Any, actual: Any) -> list[str]:
    paths: list[str] = []
    difference_paths(expected, actual, paths)
    return paths


def output_path(directory: Path, mode: str) -> Path:
    safe_mode = mode.replace("-", "_")
    return directory / f"rust-{safe_mode}.jsonl"


def locate_typescript_output(directory: Path, mode: str) -> Path:
    candidates = (
        directory / f"{mode}.jsonl",
        directory / f"{mode.replace('-', '_')}.jsonl",
        directory / f"{mode}.json",
        directory / f"{mode.replace('-', '_')}.json",
    )
    for candidate in candidates:
        if candidate.exists():
            return candidate
    names = ", ".join(str(candidate.name) for candidate in candidates)
    raise FileNotFoundError(f"no TypeScript output for {mode!r}; tried {names}")


def compare_mode(
    mode: str,
    rust_records: dict[str, dict[str, Any]],
    typescript_records: dict[str, dict[str, Any]],
    expected_ids: set[str],
) -> dict[str, Any]:
    differences: list[dict[str, Any]] = []
    removed_paths: set[str] = set()
    if set(rust_records) != expected_ids:
        differences.append(
            {
                "kind": "rust-manifest-id-set-difference",
                "missing": sorted(expected_ids - set(rust_records)),
                "unexpected": sorted(set(rust_records) - expected_ids),
            }
        )
    if set(typescript_records) != expected_ids:
        differences.append(
            {
                "kind": "typescript-manifest-id-set-difference",
                "missing": sorted(expected_ids - set(typescript_records)),
                "unexpected": sorted(set(typescript_records) - expected_ids),
            }
        )
    for record_id in sorted(set(rust_records) | set(typescript_records)):
        expected = typescript_records.get(record_id)
        actual = rust_records.get(record_id)
        if expected is None:
            differences.append({"id": record_id, "kind": "missing-typescript"})
            continue
        if actual is None:
            differences.append({"id": record_id, "kind": "missing-rust"})
            continue
        expected_is_ir = expected.get("status") == "parsed" and isinstance(
            expected.get("ir"), dict
        )
        actual_is_ir = actual.get("status") == "parsed" and isinstance(
            actual.get("ir"), dict
        )
        if not expected_is_ir or not actual_is_ir:
            differences.append(
                {
                    "id": record_id,
                    "kind": "nonparsed-or-missing-ir",
                    "typescript_status": expected.get("status"),
                    "rust_status": actual.get("status"),
                    "typescript_has_ir": expected_is_ir,
                    "rust_has_ir": actual_is_ir,
                }
            )
            continue
        expected_clean, expected_removed = remove_record_timing(expected)
        actual_clean, actual_removed = remove_record_timing(actual)
        removed_paths.update(expected_removed)
        removed_paths.update(actual_removed)
        if expected_clean != actual_clean:
            differences.append(
                {
                    "id": record_id,
                    "kind": "semantic-difference",
                    "expected_status": expected.get("status"),
                    "actual_status": actual.get("status"),
                    "first_difference_paths": bounded_difference_paths(
                        expected_clean, actual_clean
                    ),
                }
            )
    return {
        "typescript_records": len(typescript_records),
        "rust_records": len(rust_records),
        "typescript_sha256": digest(typescript_records),
        "rust_sha256": digest(rust_records),
        "removed_timing_paths": sorted(removed_paths),
        "differences": differences,
    }


def terminate_timed_out_run(process: subprocess.Popen[str]) -> list[str]:
    errors: list[str] = []
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError as error:
            errors.append(f"process-group kill failed: {error}")
    else:
        try:
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                timeout=5,
            )
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
            errors.append(f"process-tree kill failed: {error}")

    if process.poll() is None:
        try:
            process.kill()
        except ProcessLookupError:
            pass
        except OSError as error:
            errors.append(f"root kill failed: {error}")

    try:
        process.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        errors.append("process pipes remained open after cleanup")
    finally:
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError as error:
                    errors.append(f"process stream close failed: {error}")

    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        errors.append("root process remained alive after cleanup")
    return errors


def run_rust(binary: Path, manifest: Path, mode: str, output: Path) -> None:
    environment = {**os.environ, "SEM_MODE": mode}
    process = subprocess.Popen(
        [str(binary), str(manifest), str(output)],
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=os.name == "posix",
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
    )
    try:
        stdout, stderr = process.communicate(timeout=30)
    except subprocess.TimeoutExpired as error:
        cleanup_errors = terminate_timed_out_run(process)
        cleanup_detail = f"; cleanup: {', '.join(cleanup_errors)}" if cleanup_errors else ""
        raise RuntimeError(
            f"Rust full-IR run timed out after 30s for {mode}{cleanup_detail}"
        ) from error
    if process.returncode != 0:
        detail = stderr[-4000:] or stdout[-4000:]
        raise RuntimeError(f"Rust full-IR run failed for {mode}: {detail}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--rust-full-ir", type=Path, required=True)
    parser.add_argument("--typescript-output-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-cases", type=int, default=17)
    parser.add_argument("--source-commit")
    args = parser.parse_args()

    if args.output.exists():
        raise SystemExit(f"refusing to overwrite existing report: {args.output}")
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    if not isinstance(manifest, list):
        raise SystemExit("manifest must contain an array of cases")
    if len(manifest) != args.expected_cases:
        raise SystemExit(
            f"manifest contains {len(manifest)} cases; expected {args.expected_cases} "
            f"for the {args.expected_cases * len(MODES)}-case "
            f"({args.expected_cases} x {len(MODES)} modes) comparison"
        )
    valid_entries = all(
        isinstance(entry, dict) and isinstance(entry.get("id"), str)
        for entry in manifest
    )
    if not valid_entries:
        raise SystemExit("manifest entries must be objects with string ids")
    expected_ids = {entry["id"] for entry in manifest}
    if len(expected_ids) != args.expected_cases:
        raise SystemExit("manifest ids must be unique")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    report: dict[str, Any] = {
        "comparator_sha256": file_digest(Path(__file__).resolve()),
        "manifest_sha256": hashlib.sha256(args.manifest.read_bytes()).hexdigest(),
        "rust_binary_sha256": file_digest(args.rust_full_ir),
        "source_commit": args.source_commit,
        "expected_cases": args.expected_cases,
        "modes": {},
    }
    with tempfile.TemporaryDirectory(prefix="rea-full-semantic-diff-") as work_dir:
        work = Path(work_dir)
        for mode in MODES:
            rust_output = output_path(work, mode)
            run_rust(args.rust_full_ir, args.manifest, mode, rust_output)
            typescript_output = locate_typescript_output(args.typescript_output_dir, mode)
            report["modes"][mode] = compare_mode(
                mode,
                read_records(rust_output),
                read_records(typescript_output),
                expected_ids,
            )
            report["modes"][mode]["typescript_output_sha256"] = file_digest(typescript_output)

    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    differences = sum(len(mode["differences"]) for mode in report["modes"].values())
    print(json.dumps({"modes": len(MODES), "differences": differences}))
    return 1 if differences else 0


if __name__ == "__main__":
    sys.exit(main())
