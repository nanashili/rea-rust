#!/usr/bin/env python3
"""Capture reproducible host and selected-artifact provenance for a benchmark.

The collector reads the plan and hashes only files explicitly named by it, plus
each application's Info.plist and its canonical executable. It never walks an
application bundle recursively and never records the ambient environment.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import shutil
import subprocess
import sys
from typing import Any


HASH_CHUNK_BYTES = 1024 * 1024
COMMAND_OUTPUT_LIMIT = 4096


@dataclass(frozen=True)
class FileObservation:
    path: str
    resolved_path: str
    size_bytes: int
    mtime_ns: int
    device: int
    inode: int
    sha256: str
    changed_during_read: bool


def sha256_json(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def sha256_file(path: Path) -> FileObservation:
    before = path.stat()
    digest = hashlib.sha256()

    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(HASH_CHUNK_BYTES), b""):
            digest.update(chunk)

    after = path.stat()
    changed = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    )
    return FileObservation(
        path=str(path),
        resolved_path=str(path.resolve()),
        size_bytes=after.st_size,
        mtime_ns=after.st_mtime_ns,
        device=after.st_dev,
        inode=after.st_ino,
        sha256=digest.hexdigest(),
        changed_during_read=changed,
    )


def run_public_command(command: list[str]) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"command": command, "available": False, "error": str(error)}

    output = (completed.stdout or completed.stderr).strip()
    return {
        "command": command,
        "available": completed.returncode == 0,
        "returncode": completed.returncode,
        "output": output[:COMMAND_OUTPUT_LIMIT],
    }


def read_machine_memory_bytes() -> int | None:
    try:
        import psutil

        return int(psutil.virtual_memory().total)
    except (ImportError, AttributeError, OSError):
        result = run_public_command(["sysctl", "-n", "hw.memsize"])
        try:
            return int(result.get("output", ""))
        except ValueError:
            return None


def collect_host() -> dict[str, Any]:
    disk = shutil.disk_usage(Path.cwd())
    host = {
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "cpu_count": os.cpu_count(),
        "memory_bytes": read_machine_memory_bytes(),
        "disk_free_bytes_at_capture": disk.free,
        "disk_total_bytes_at_capture": disk.total,
        "commands": {
            "sw_vers": run_public_command(["sw_vers"]),
            "sysctl_cpu": run_public_command(["sysctl", "-n", "hw.ncpu"]),
            "sysctl_cpu_model": run_public_command(["sysctl", "-n", "machdep.cpu.brand_string"]),
            "sysctl_hardware_model": run_public_command(["sysctl", "-n", "hw.model"]),
            "power": run_public_command(["pmset", "-g", "batt"]),
            "thermal": run_public_command(["pmset", "-g", "therm"]),
        },
    }
    try:
        import psutil

        host["psutil_version"] = psutil.__version__
        host["load_average"] = list(psutil.getloadavg())
    except (ImportError, AttributeError, OSError):
        host["psutil_version"] = None
    return host


def walk_values(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for child in value for item in walk_values(child)]
    if isinstance(value, dict):
        return [item for child in value.values() for item in walk_values(child)]
    return []


def canonical_bundle_files(bundle: Path) -> list[Path]:
    plist_path = bundle / "Contents" / "Info.plist"
    if not plist_path.is_file():
        return []

    files = [plist_path]
    try:
        with plist_path.open("rb") as stream:
            metadata = plistlib.load(stream)
    except (OSError, plistlib.InvalidFileException, ValueError):
        return files

    executable = metadata.get("CFBundleExecutable")
    if isinstance(executable, str) and executable:
        executable_path = bundle / "Contents" / "MacOS" / executable
        if executable_path.is_file():
            files.append(executable_path)
    return files


def bundle_metadata(bundle: Path) -> dict[str, Any]:
    plist_path = bundle / "Contents" / "Info.plist"
    result: dict[str, Any] = {"path": str(bundle), "info_plist": str(plist_path)}
    if not plist_path.is_file():
        result["available"] = False
        return result

    try:
        with plist_path.open("rb") as stream:
            metadata = plistlib.load(stream)
    except (OSError, plistlib.InvalidFileException, ValueError) as error:
        result["available"] = False
        result["error"] = str(error)
        return result

    result.update(
        {
            "available": True,
            "bundle_identifier": metadata.get("CFBundleIdentifier"),
            "short_version": metadata.get("CFBundleShortVersionString"),
            "build_version": metadata.get("CFBundleVersion"),
            "executable": metadata.get("CFBundleExecutable"),
        }
    )
    return result


def selected_paths(plan: dict[str, Any]) -> tuple[list[Path], list[dict[str, Any]]]:
    candidates: set[Path] = set()
    bundle_records: list[dict[str, Any]] = []

    for workflow in plan.get("workflows", []):
        target = workflow.get("target")
        if isinstance(target, str) and target.startswith("/"):
            target_path = Path(target)
            if target_path.is_dir():
                bundle_records.append({"path": str(target_path), "exists": True, "is_directory": True})
                candidates.update(canonical_bundle_files(target_path))
            elif target_path.is_file():
                candidates.add(target_path)

        for value in workflow.get("input_files", []):
            path = Path(value)
            if path.is_absolute() and path.is_file():
                candidates.add(path)

        for case in workflow.get("cases", []):
            arguments = case.get("arguments", {})
            for value in walk_values(arguments):
                if not value.startswith("/"):
                    continue
                path = Path(value)
                if path.is_file():
                    candidates.add(path)

    return sorted(candidates), bundle_records


def observe_files(paths: list[Path]) -> list[dict[str, Any]]:
    observations = []
    for path in paths:
        try:
            observations.append(vars(sha256_file(path)))
        except (OSError, ValueError) as error:
            observations.append({"path": str(path), "error": str(error)})
    return observations


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--rea", required=True, type=Path)
    parser.add_argument("--worker", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    plan_bytes = args.plan.read_bytes()
    plan = json.loads(plan_bytes)
    selected, bundles = selected_paths(plan)
    runner_path = Path(__file__).resolve().with_name("run_mcp.py")

    artifact_paths = [args.plan, args.rea, args.worker, runner_path, *selected]
    before = observe_files(artifact_paths)
    after = observe_files(artifact_paths)
    output = {
        "schema_version": 1,
        "captured_at_utc": datetime.now(timezone.utc).isoformat(),
        "plan_sha256": hashlib.sha256(plan_bytes).hexdigest(),
        "plan_path": str(args.plan.resolve()),
        "rea_path": str(args.rea.resolve()),
        "worker_path": str(args.worker.resolve()),
        "runner_path": str(runner_path),
        "host": collect_host(),
        "bundle_targets": [bundle_metadata(Path(item["path"])) for item in bundles],
        "selected_files_before": before,
        "selected_files_after": after,
        "selected_file_count": len(selected),
    }
    output["manifest_sha256"] = sha256_json(output)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
