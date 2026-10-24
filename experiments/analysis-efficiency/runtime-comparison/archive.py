#!/usr/bin/env python3
"""Preserve compact benchmark evidence without committing runtime binaries."""

from __future__ import annotations

import argparse
import json
import platform
import shutil
from pathlib import Path

import psutil

from prepare import manifest_digest, sha256, write_json


def artifact(path: Path) -> dict[str, object]:
    return {"path": str(path), "bytes": path.stat().st_size, "sha256": sha256(path)}


def archive_provenance(prepared: Path, output: Path) -> dict:
    provenance_path = prepared / "provenance.json"
    original = json.loads(provenance_path.read_text())
    git = original["git"]
    receipt = {
        key: value for key, value in original.items()
        if key not in {"git", "builds"}
    }
    receipt["original_provenance"] = artifact(provenance_path)
    receipt["git"] = {
        key: value for key, value in git.items() if "status" not in key
    }
    receipt["git"]["repository_dirty"] = bool(git["repository_status"])
    receipt["git"]["native_dirty"] = bool(git["native_status"])
    receipt["builds"] = {
        "typescript": {
            "status": original["builds"]["typescript"]["status"],
            "dist_manifest_sha256": original["builds"]["typescript"]["result"]["manifest_sha256"],
            "dist_files": len(original["builds"]["typescript"]["result"]["manifest"]),
        },
        "native": original["builds"]["native"],
    }
    receipt["source_manifests"] = {}
    for name in ["native-source-manifest.json", "bridge-support-source-manifest.json"]:
        source = prepared / name
        rows = json.loads(source.read_text())
        shutil.copy2(source, output / name)
        receipt["source_manifests"][name] = {
            **artifact(source), "files": len(rows), "canonical_manifest_sha256": manifest_digest(rows),
        }
    receipt["build_logs"] = [artifact(path) for path in sorted(prepared.glob("*build*.log"))]
    receipt["measurement_runtime"] = {
        "python": platform.python_version(), "psutil": psutil.__version__,
    }
    receipt["reconstruction_limit"] = (
        "Native includes uncommitted source. Its Git commit alone cannot recreate this build; "
        "the retained local snapshot and source manifests identify the measured files. "
        "Large original provenance, build logs and raw protocol transcripts remain local."
    )
    return receipt


def archive_measurements(prepared: Path, measured: Path, output: Path) -> None:
    results = json.loads((measured / "results.json").read_text())
    if results.get("qualification_only"):
        raise ValueError("qualification results cannot be archived as measurements")
    if not results["rows"] or any(row["status"] != "success" for row in results["rows"]):
        raise ValueError("resolve or separately report failed measurements before archiving")
    for comparison in results["comparisons"]:
        if comparison["task"] == "catalog":
            continue
        equivalent = comparison.get(
            "complete_json_semantic_equal", comparison["exact_structural_equal"]
        )
        if not comparison["both_completed"] or not equivalent:
            raise ValueError(f"analysis results differ: {comparison['task']}")
    if sha256(prepared / "provenance.json") != results["provenance_sha256"]:
        raise ValueError("prepared provenance changed after measurement")

    transcripts = [artifact(Path(row["transcript"])) for row in results["rows"] if "transcript" in row]
    write_json(output / "transcript-manifest.json", transcripts)
    shutil.copy2(measured / "results.json", output / "raw-results.json")
    shutil.copy2(prepared / "native-doctor.json", output / "native-doctor.json")


def archive_qualification(prepared: Path, output: Path) -> None:
    qualifications = []
    for source in sorted(prepared.glob("qualification*/results.json")):
        document = json.loads(source.read_text())
        qualifications.append({
            "receipt": artifact(source),
            "qualification_only": document["qualification_only"],
            "failures": [
                {key: row[key] for key in ["task", "sample", "lane", "error"] if key in row}
                for row in document["rows"] if row["status"] != "success"
            ],
        })
    failure = prepared / "qualification" / "rust-stress-error.json"
    write_json(output / "qualification.json", {
        "runs": qualifications,
        "oversized_rust_failure": json.loads(failure.read_text()) if failure.exists() else None,
        "note": "All qualification timings are excluded from the measured summaries.",
    })


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--prepared", type=Path, required=True)
    parser.add_argument("--measured", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    prepared = args.prepared.resolve()
    measured = args.measured.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)

    provenance = archive_provenance(prepared, output)
    archive_measurements(prepared, measured, output)
    archive_qualification(prepared, output)
    write_json(output / "provenance.json", provenance)


if __name__ == "__main__":
    main()
