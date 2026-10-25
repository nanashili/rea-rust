#!/usr/bin/env python3
"""Finalize the local benchmark tool map from the catalog and raw receipts.

This script is deliberately data driven.  It does not infer successful
coverage from a plan entry: a tool is measured only when a receipt contains a
matching ``tools/call`` row.  Pass ``--raw`` once per independent benchmark
series; each series is checked against its own plan and round count before
observations are aggregated.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from receipt_utils import error_summary


DEFAULT_CATALOG = Path("/tmp/rea-benchmark-catalog.json")
DEFAULT_RAW = Path("docs/benchmarks/local-applications-2026-10-25-raw.json")
DEFAULT_COVERAGE = Path("docs/benchmarks/local-applications-2026-10-25-coverage.json")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def catalog_tools(catalog: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Return the advertised tools from either supported catalog envelope."""
    candidates: Any = catalog.get("tools")
    if not isinstance(candidates, list):
        result = catalog.get("result")
        candidates = result.get("tools") if isinstance(result, dict) else None
    if not isinstance(candidates, list):
        raise ValueError("catalog has no tools array")

    tools: dict[str, dict[str, Any]] = {}
    duplicates: set[str] = set()
    for tool in candidates:
        if not isinstance(tool, dict) or not isinstance(tool.get("name"), str):
            continue
        name = tool["name"]
        if name in tools:
            duplicates.add(name)
        tools[name] = tool
    if duplicates:
        raise ValueError(f"catalog contains duplicate tool names: {', '.join(sorted(duplicates))}")
    return tools


def catalog_tool_list(catalog: dict[str, Any]) -> list[dict[str, Any]]:
    candidates = catalog.get("tools")
    if not isinstance(candidates, list):
        result = catalog.get("result")
        candidates = result.get("tools") if isinstance(result, dict) else None
    if not isinstance(candidates, list):
        raise ValueError("catalog has no tools array")
    return candidates


def canonical_catalog_sha256(catalog: dict[str, Any]) -> str:
    response = {
        "jsonrpc": "2.0",
        "id": 2,
        "result": {"tools": catalog_tool_list(catalog)},
    }
    encoded = json.dumps(response, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def embedded_catalog_hashes(raw: dict[str, Any]) -> set[str]:
    found: set[str] = set()

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if key == "catalog_sha256" and isinstance(child, str):
                    found.add(child)
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(raw)
    return found


def receipt_calls(
    raw: dict[str, Any],
    *,
    source_series: str,
    source_raw: Path,
) -> dict[str, list[dict[str, Any]]]:
    calls: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for receipt in raw.get("receipts", []):
        for call in receipt.get("calls", []):
            request = call.get("request", {})
            params = request.get("params", {})
            if request.get("method") != "tools/call" or not params.get("name"):
                continue

            error_code, error_reason = error_summary(call.get("error"))
            calls[params["name"]].append(
                {
                    "workflow": receipt.get("workflow", {}).get("name", "unknown"),
                    "round": receipt.get("round"),
                    "source_series": source_series,
                    "source_raw": str(source_raw),
                    "label": call.get("label"),
                    "status": str(call.get("status") or "unknown"),
                    "wall_ms": call.get("wall_ms"),
                    "output_bytes": call.get("output_bytes"),
                    "response_sha256": call.get("response_sha256"),
                    "error_code": error_code,
                    "error_reason": error_reason,
                }
            )

    return calls


def unmeasured_reason(tool: dict[str, Any], entry: dict[str, Any]) -> tuple[str, str]:
    name = tool["name"]
    classification = entry.get("classification")

    if name == "inspect_binary_layout":
        return (
            "unmeasured-input",
            "The selected host is macOS arm64; this operation's shipped initial profile accepts ELF64 x86-64 Linux artifacts, and no compatible input was selected.",
        )

    if name == "inspect_il2cpp_metadata":
        return (
            "unmeasured-input",
            "The selected Unity installation has managed PE assemblies but no selected Unity global-metadata.dat input; native IL2CPP metadata is therefore unavailable for this run.",
        )

    if name == "inspect_pe_resources":
        return (
            "not-included-in-this-benchmark",
            "A compatible Unity managed PE DLL is present, but no inspect_pe_resources call was included in the frozen workflows.",
        )

    if name == "demangle_swift":
        return (
            "not-included-in-this-benchmark",
            "No selected artifact supplied an artifact-backed Swift symbol; the standalone demangler utility lane was not included.",
        )

    if name == "inspect_native_data_type":
        return (
            "not-included-in-this-benchmark",
            "The selected native workflows use the headless Ghidra Rust provider, which reports no type-editor/type-recovery capability; no compatible typed-data selector was available.",
        )

    if name == "extract_artifact":
        return (
            "not-included-in-this-benchmark",
            "No bounded archive/package extraction fixture was selected; this operation creates a fresh REA-owned extraction directory and was omitted from the read-only artifact lanes.",
        )

    if name == "recover_javascript_sources":
        return (
            "unmeasured-input",
            "The selected local JavaScript files do not establish a compatible recovery lane: the shipped tool requires Wakaru and Linux x64 support plus a fresh output directory, and no such source bundle/output fixture was selected.",
        )

    if name in {"analyze_web_bundle", "inspect_web_page", "list_browser_targets", "export_web_scripts", "discover_webmcp_tools"}:
        return (
            "not-included-in-this-benchmark",
            "This operation requires a live CDP/browser target or retained web capture; the frozen benchmark is limited to local shipped artifacts and contains no compatible browser session.",
        )

    if name in {"record_unknown", "update_unknown", "verify_unknown_resolution"}:
        return (
            "not-included-in-this-benchmark",
            "A retained Evidence session existed, but no composed reconstruction/unknown contract supplied a stable unknown identifier and revision for this operation.",
        )

    if name in {"trace_web_module_imports", "trace_web_source_location"}:
        return (
            "not-included-in-this-benchmark",
            "This operation requires an exported web-script manifest and, for source-location tracing, a paired source map; no such retained web capture was selected.",
        )

    if name in {"inspect_web_event_listeners", "list_javascript_runtime_targets", "reconcile_javascript_runtime"}:
        return (
            "not-included-in-this-benchmark",
            "This operation requires a live or retained JavaScript runtime/browser target; local Electron files alone do not satisfy its input contract.",
        )

    if name in {"inspect_wasm_artifact", "compare_wasm_interfaces"}:
        return (
            "unmeasured-input" if name == "inspect_wasm_artifact" else "not-included-in-this-benchmark",
            "No selected artifact is a WASM module; no compatible input or pair was available for this operation.",
        )

    if name == "inspect_evm_interface":
        return (
            "unmeasured-input",
            "No selected artifact is EVM bytecode or an EVM deployment capture.",
        )

    if name in {"project_managed_application_graph", "compare_managed_members", "verify_managed_native_boundaries", "import_managed_reconstruction"}:
        return (
            "unmeasured-input",
            "The selected Unity managed calls did not produce the complete paired authenticated Evidence group required by this composition operation.",
        )

    if name in {"inspect_android_package", "search_android_classes", "inspect_android_class", "inspect_android_method", "trace_android_references"}:
        return (
            "unmeasured-input",
            "No APK or Android class/method Evidence was selected on this macOS local-artifact run.",
        )

    if name in {"inspect_jeb_client", "open_jeb_project", "list_jeb_units", "decompile_jeb_item"}:
        return (
            "unmeasured-input",
            "No caller-supplied JEB client/project/unit was selected; these operations cannot be inferred from the Unity managed DLLs.",
        )

    if name in {"identify_flutter_build", "inspect_dart_aot", "decode_android_resources", "inspect_apktool_client"}:
        return (
            "unmeasured-input",
            "No Flutter/Dart AOT, APK resource, or Apktool/JADX-compatible artifact was selected.",
        )

    if classification == "optional_artifact":
        return (
            "unmeasured-input",
            "No selected local artifact in the frozen workflows supplied the required format or fixture.",
        )

    if classification == "session_evidence":
        return (
            "not-included-in-this-benchmark",
            "A retained Evidence session was available, but this operation was not included in the frozen workflow cases.",
        )

    if name.startswith(("compare_", "trace_")):
        return (
            "not-included-in-this-benchmark",
            "This relationship operation needs a specific paired artifact or retained Evidence selection that was not included in the frozen workflows.",
        )

    if name.startswith(("inspect_native_", "analyze_function", "procedure_", "read_function_", "xrefs", "get_call_graph", "batch_decompile", "search_bytes")):
        return (
            "not-included-in-this-benchmark",
            "No recorded call exercised this operation in the frozen workflows; prerequisite availability is unknown.",
        )

    if name in {"inspect_macho", "inspect_signature", "list_architectures", "list_segments", "list_procedures", "list_strings", "search_procedures", "search_strings", "binary_overview", "address_to_file_offset", "read_bytes"}:
        return (
            "not-included-in-this-benchmark",
            "No frozen workflow invoked this read-only operation with a compatible selected target.",
        )

    return (
        "not-included-in-this-benchmark",
        "No frozen workflow invoked this operation, so no runtime coverage was observed.",
    )


def receipt_completeness(raw: dict[str, Any], *, source_series: str, source_raw: Path) -> dict[str, Any]:
    receipts = [item for item in raw.get("receipts", []) if isinstance(item, dict)]
    rounds = raw.get("rounds")
    plan = next((item.get("plan") for item in receipts if isinstance(item.get("plan"), dict)), {})
    planned_names = [item.get("name") for item in plan.get("workflows", []) if isinstance(item, dict) and isinstance(item.get("name"), str)]
    expected_pairs = {(name, round_number) for name in planned_names for round_number in range(1, (rounds or 0) + 1)}
    observed_pairs = [(item.get("workflow", {}).get("name"), item.get("round")) for item in receipts]
    pair_counts = Counter(observed_pairs)
    actual_pairs = set(observed_pairs)
    duplicates = [{"workflow": pair[0], "round": pair[1], "count": count} for pair, count in pair_counts.items() if count > 1]
    missing = [{"workflow": pair[0], "round": pair[1]} for pair in sorted(expected_pairs - actual_pairs, key=str)]
    unknown = sorted({str(pair[0]) for pair in actual_pairs if pair[0] not in planned_names})
    expected = len(expected_pairs) if isinstance(rounds, int) else None
    observed = len(receipts)
    warnings = []
    if expected is None or len(receipts) != expected:
        warnings.append("receipt count does not match planned workflow-round coverage")
    if duplicates:
        warnings.append("duplicate workflow-round receipts are present")
    if missing:
        warnings.append("planned workflow-round receipts are missing")
    if unknown:
        warnings.append("receipts contain workflows absent from the plan")
    return {
        "status": "complete" if expected is not None and not duplicates and not missing and not unknown and expected == observed else "partial-or-unknown",
        "expected_receipts": expected,
        "observed_receipts": observed,
        "missing_receipts": max(expected - observed, 0) if expected is not None else None,
        "workflow_count": len(planned_names),
        "rounds": rounds,
        "unique_workflow_rounds": len(actual_pairs),
        "duplicates": duplicates,
        "missing_workflow_rounds": missing,
        "unknown_workflows": unknown,
        "warnings": warnings,
        "source_series": source_series,
        "source_raw": str(source_raw),
    }


def series_name(path: Path, used_names: set[str]) -> str:
    base_name = path.stem or "raw"
    name = base_name
    suffix = 2
    while name in used_names:
        name = f"{base_name}-{suffix}"
        suffix += 1
    used_names.add(name)
    return name


def load_series(raw_paths: list[Path]) -> list[dict[str, Any]]:
    used_names: set[str] = set()
    series: list[dict[str, Any]] = []
    for raw_path in raw_paths:
        source_series = series_name(raw_path, used_names)
        raw = json.loads(raw_path.read_text())
        if not isinstance(raw, dict):
            raise ValueError(f"raw benchmark series is not an object: {raw_path}")
        series.append(
            {
                "name": source_series,
                "path": raw_path,
                "raw": raw,
                "completeness": receipt_completeness(
                    raw,
                    source_series=source_series,
                    source_raw=raw_path,
                ),
            }
        )
    return series


def aggregate_series_calls(series: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    calls: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in series:
        series_calls = receipt_calls(
            item["raw"],
            source_series=item["name"],
            source_raw=item["path"],
        )
        for tool_name, observations in series_calls.items():
            calls[tool_name].extend(observations)
    return calls


def aggregate_completeness(series: list[dict[str, Any]]) -> dict[str, Any]:
    details = [item["completeness"] for item in series]
    warnings = [
        f"{item['source_series']}: {warning}"
        for item in details
        for warning in item["warnings"]
    ]
    expected = [item["expected_receipts"] for item in details]
    observed = sum(item["observed_receipts"] for item in details)
    expected_total = sum(value for value in expected if isinstance(value, int)) if all(isinstance(value, int) for value in expected) else None
    return {
        "status": "complete" if expected_total is not None and not warnings and expected_total == observed else "partial-or-unknown",
        "expected_receipts": expected_total,
        "observed_receipts": observed,
        "missing_receipts": max(expected_total - observed, 0) if expected_total is not None else None,
        "series_count": len(details),
        "series": details,
        "warnings": warnings,
    }


def update_tool_entries(
    coverage_tools: list[dict[str, Any]],
    advertised: dict[str, dict[str, Any]],
    calls: dict[str, list[dict[str, Any]]],
) -> Counter[str]:
    for entry in coverage_tools:
        name = entry["name"]
        tool = advertised[name]
        observed = calls.get(name, [])
        if observed:
            statuses = Counter(call["status"] for call in observed)
            success = statuses.get("success", 0)
            failure = sum(count for status, count in statuses.items() if status != "success")
            measurement = "partial" if success and failure else "measured-success" if success else "failure-only"
            entry["status"] = measurement
            entry["measurement"] = measurement
            entry["reason"] = (
                f"Observed {len(observed)} call(s) across "
                f"{len({(c['source_series'], c['workflow'], c['round']) for c in observed})} "
                f"series/workflow-round(s): {success} success and {failure} non-success result(s)."
            )
            entry["observations"] = observed
            continue

        if entry.get("classification") in {"target_mutation", "live_execution", "external_device"}:
            entry["status"] = "excluded"
            entry["measurement"] = "excluded"
            entry["reason"] = "Outside the frozen read-only local artifact benchmark scope."
            entry.pop("observations", None)
            continue

        status, reason = unmeasured_reason(tool, entry)
        entry["status"] = status
        entry["measurement"] = "unmeasured"
        entry["reason"] = reason
        entry.pop("observations", None)

    return Counter(entry["status"] for entry in coverage_tools)


def validate_catalog_identity(
    catalog: dict[str, Any],
    series: list[dict[str, Any]],
) -> tuple[dict[str, dict[str, Any]], str, set[str]]:
    advertised = catalog_tools(catalog)
    canonical_hash = canonical_catalog_sha256(catalog)
    embedded_hashes = set().union(
        *(embedded_catalog_hashes(item["raw"]) for item in series)
    )
    if embedded_hashes and embedded_hashes != {canonical_hash}:
        raise ValueError(
            "raw receipt catalog hashes do not match the canonical catalog: "
            f"embedded={sorted(embedded_hashes)} canonical={canonical_hash}"
        )
    return advertised, canonical_hash, embedded_hashes


def validate_coverage_tools(
    coverage: dict[str, Any],
    advertised: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    coverage_tools = coverage.get("tools")
    if not isinstance(coverage_tools, list):
        raise ValueError("coverage has no tools array")
    coverage_names = [entry.get("name") for entry in coverage_tools if isinstance(entry, dict)]
    if any(not isinstance(name, str) or not name for name in coverage_names):
        raise ValueError("coverage contains a tool without a name")
    duplicate_coverage_names = [name for name, count in Counter(coverage_names).items() if count > 1]
    if duplicate_coverage_names:
        raise ValueError(f"coverage contains duplicate tool names: {', '.join(sorted(duplicate_coverage_names))}")
    missing_from_coverage = sorted(set(advertised) - set(coverage_names))
    extra_in_coverage = sorted(set(coverage_names) - set(advertised))
    if missing_from_coverage or extra_in_coverage:
        raise ValueError(
            "coverage/catalog tool sets differ: "
            f"missing={missing_from_coverage[:5]} extra={extra_in_coverage[:5]}"
        )
    return coverage_tools


def update_source_metadata(
    coverage: dict[str, Any],
    catalog: dict[str, Any],
    catalog_path: Path,
    raw_paths: list[Path],
    advertised: dict[str, dict[str, Any]],
    canonical_hash: str,
    embedded_hashes: set[str],
) -> None:
    coverage["source"]["catalog_sha256"] = canonical_hash
    coverage["source"]["catalog_file_sha256"] = sha256(catalog_path)
    file_format = (
        "REA catalog envelope: initialize + pages + tools"
        if "initialize" in catalog and "pages" in catalog
        else "JSON-RPC response: jsonrpc + id + result.tools"
    )
    coverage["source"]["catalog_representation"] = {
        "file_format": file_format,
        "canonical_benchmark_format": "JSON-RPC 2.0 response with id 2 and result.tools",
        "canonical_sha256": canonical_hash,
        "embedded_raw_hashes": sorted(embedded_hashes),
        "advertised_tool_count": len(advertised),
    }
    coverage["source"]["advertised_tool_count"] = len(advertised)
    coverage["source"]["implemented_tool_count"] = None
    coverage["source"]["raw_receipts"] = [str(path) for path in raw_paths]


def summarize_call_metrics(
    coverage: dict[str, Any],
    measured: Counter[str],
    series: list[dict[str, Any]],
    calls: dict[str, list[dict[str, Any]]],
    completeness: dict[str, Any],
) -> None:
    coverage["summary"] = dict(measured)
    observed_call_rows = sum(len(rows) for rows in calls.values())
    total_call_rows = sum(
        len(receipt.get("calls", []))
        for item in series
        for receipt in item["raw"].get("receipts", [])
    )
    coverage["summary"]["observed_call_rows"] = observed_call_rows
    coverage["summary"]["discovery_call_rows"] = total_call_rows - observed_call_rows
    coverage["summary"]["total_call_rows"] = total_call_rows
    coverage["summary"]["run_completeness"] = completeness


def finalize(catalog_path: Path, raw_paths: list[Path], coverage_path: Path) -> None:
    catalog = json.loads(catalog_path.read_text())
    coverage = json.loads(coverage_path.read_text())
    series = load_series(raw_paths)
    advertised, canonical_hash, embedded_hashes = validate_catalog_identity(catalog, series)
    coverage_tools = validate_coverage_tools(coverage, advertised)
    calls = aggregate_series_calls(series)

    measured = update_tool_entries(coverage_tools, advertised, calls)
    completeness = aggregate_completeness(series)
    coverage["status"] = (
        "finalized-from-complete-receipts"
        if completeness["status"] == "complete"
        else "finalized-from-partial-or-unknown-receipts"
    )
    update_source_metadata(
        coverage,
        catalog,
        catalog_path,
        raw_paths,
        advertised,
        canonical_hash,
        embedded_hashes,
    )
    summarize_call_metrics(coverage, measured, series, calls, completeness)

    coverage_path.write_text(json.dumps(coverage, indent=2) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    parser.add_argument(
        "--raw",
        dest="raw_paths",
        action="append",
        type=Path,
        default=None,
        help="raw receipt series; repeat for independent plans (defaults to the main series)",
    )
    parser.add_argument("--coverage", type=Path, default=DEFAULT_COVERAGE)
    args = parser.parse_args()
    finalize(args.catalog, args.raw_paths or [DEFAULT_RAW], args.coverage)


if __name__ == "__main__":
    main()
