#!/usr/bin/env python3
"""Compare frozen benchmark receipts with a later verification run."""
from __future__ import annotations

import argparse
import json
import re
import statistics
from collections import Counter
from pathlib import Path
from typing import Any


def parse_series(value: str) -> tuple[str, Path]:
    name, separator, path = value.partition("=")
    if not separator or not name or not path:
        raise argparse.ArgumentTypeError("series arguments must use NAME=PATH")
    return name, Path(path)


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def planned_pairs(raw: dict[str, Any]) -> set[tuple[str, int]]:
    receipts = [r for r in raw.get("receipts", []) if isinstance(r, dict)]
    plan = next((r.get("plan") for r in receipts if isinstance(r.get("plan"), dict)), {})
    rounds = raw.get("rounds")
    if not isinstance(rounds, int):
        return set()
    names = [w.get("name") for w in plan.get("workflows", []) if isinstance(w, dict) and isinstance(w.get("name"), str)]
    return {(name, round_number) for name in names for round_number in range(1, rounds + 1)}


HEADLESS_GHIDRA_TOOLS = {
    "address_to_file_offset",
    "analyze_function",
    "find_xrefs_to_name",
    "get_navigation_context",
    "get_objc_classes",
    "get_objc_protocols",
    "inspect_native_api",
    "inspect_native_dispatch_metadata",
    "inspect_native_load_image",
    "list_names",
    "procedure_callers",
    "procedure_callees",
    "procedure_info",
    "resolve_containing_procedure",
    "resolve_native_call_targets",
    "search_bytes",
    "trace_feature",
}

METRIC_NAMES = (
    "wall_ms",
    "wait4_cpu_ms",
    "harness_cpu_ms",
    "sampled_family_cpu_ms",
    "sampled_family_peak_rss_mib",
)



def error_info(value: Any, tool: str = "") -> tuple[str, str, str, str]:
    if isinstance(value, str):
        if value.startswith("MemoryError:"):
            return "harness_rss_limit", "harness", value, "harness_resource_limit"
        return "unknown", "harness", value, "unknown"
    if isinstance(value, dict):
        for item in value.get("content", []):
            if not isinstance(item, dict) or not isinstance(item.get("text"), str):
                continue
            try:
                parsed = json.loads(item["text"])
            except (TypeError, ValueError):
                continue
            error = parsed.get("error") if isinstance(parsed, dict) else None
            if isinstance(error, dict):
                code = str(error.get("code") or "unknown")
                category = str(error.get("category") or "unknown")
                message = str(error.get("message") or "")
                details = error.get("details") if isinstance(error.get("details"), dict) else {}
                provider_id = str(
                    details.get("provider_id")
                    or details.get("requested_provider_id")
                    or ""
                )
                is_instruction_exception = tool == "inspect_native_instruction"
                is_headless_ghidra = (
                    code == "capability_unavailable"
                    and not is_instruction_exception
                    and (provider_id == "ghidra-rust" or tool in HEADLESS_GHIDRA_TOOLS)
                )
                family = "headless_ghidra_unsupported" if is_headless_ghidra else "other"
                return code, category, message, family
    return "unknown", "unknown", "unstructured failure", "unknown"


def receipt_key(receipt: dict[str, Any]) -> tuple[str, int]:
    return str(receipt.get("workflow", {}).get("name", "unknown")), int(receipt.get("round", 0))


def outcome(receipt: dict[str, Any]) -> str:
    calls = [c for c in receipt.get("calls", []) if isinstance(c, dict)]
    failed = sum(c.get("status") != "success" for c in calls)
    if failed and any(c.get("status") == "success" for c in calls):
        return "failed_with_some_calls_working"
    if failed == 0 and receipt.get("status") == "success":
        return "protocol_success"
    return "failed"


def response_json(call_file: Path) -> dict[str, Any] | None:
    try:
        envelope = json.loads(call_file.read_text())
        response = envelope.get("response", {})
        result = response.get("result", {})
        candidates: list[dict[str, Any]] = []
        structured = result.get("structuredContent")
        if isinstance(structured, dict):
            candidates.append(structured)
        text = "".join(
            item.get("text", "")
            for item in result.get("content", [])
            if isinstance(item, dict) and item.get("type") == "text"
        )
        if text:
            try:
                value = json.loads(text)
            except json.JSONDecodeError:
                value = None
            if isinstance(value, dict):
                candidates.append(value)
        for candidate in candidates:
            value = candidate.get("result") if isinstance(candidate.get("result"), dict) else candidate
            if isinstance(value, dict) and "operation" in value and "normalized_result" in value:
                return value
        return None
    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        return None


def explicit_semantics(value: dict[str, Any], call_file: Path) -> dict[str, Any] | None:
    """Expose provider coverage facts without treating them as proof."""
    operation = value.get("operation")
    normalized = value.get("normalized_result")
    if not isinstance(operation, str) or not isinstance(normalized, dict):
        return None

    coverage = normalized.get("coverage")
    limitations = normalized.get("limitations")
    result: dict[str, Any] = {
        "operation": operation,
        "call": call_file.name,
        "status": "semantic_unknown",
        "independent_validation": "not_performed",
        "provider_coverage_status": None,
        "limitations": [],
    }
    if isinstance(limitations, list):
        result["limitations"] = [str(item)[:240] for item in limitations if isinstance(item, str)]

    known_coverage_operation = operation in {
        "inspect_analysis_view",
        "inspect_pe_resources",
        "list_procedures",
    }
    if not known_coverage_operation or not isinstance(coverage, dict):
        return result
    if isinstance(coverage.get("status"), str):
        result["provider_coverage_status"] = coverage["status"]
    return result


def semantic_coverage(work_dir: Path | None) -> dict[tuple[str, int], dict[str, Any]]:
    coverage: dict[tuple[str, int], dict[str, Any]] = {}
    if work_dir is None:
        return coverage
    for call_file in work_dir.glob("**/call-*.json"):
        value = response_json(call_file)
        if not value:
            continue
        match = re.match(r"^(.*)-round-(\d+)$", call_file.parent.name)
        if not match:
            continue
        key = (match.group(1), int(match.group(2)))
        statuses = coverage.setdefault(
            key,
            {
                "statuses": Counter(),
                "provider_coverage_statuses": Counter(),
                "provider_coverage_calls": [],
                "limitations": [],
            },
        )
        semantics = explicit_semantics(value, call_file)
        if semantics is None:
            continue
        status = semantics["status"]
        statuses["statuses"][status] += 1
        provider_status = semantics.get("provider_coverage_status")
        if isinstance(provider_status, str):
            statuses["provider_coverage_statuses"][provider_status] += 1
            statuses["provider_coverage_calls"].append(call_file.name)
        statuses["limitations"].extend(semantics["limitations"])
    for value in coverage.values():
        if value["limitations"]:
            value["limitations"] = sorted(set(value["limitations"]))
        for field in ("provider_coverage_calls",):
            value[field] = sorted(set(value[field]))
    return coverage


def receipt_summary(
    raw: dict[str, Any],
    expected: set[tuple[str, int]],
    semantic_by_receipt: dict[tuple[str, int], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    receipts = [r for r in raw.get("receipts", []) if isinstance(r, dict)]
    grouped: dict[tuple[str, int], list[dict[str, Any]]] = {}
    for receipt in receipts:
        grouped.setdefault(receipt_key(receipt), []).append(receipt)
    duplicates = sorted(key for key, values in grouped.items() if len(values) > 1)
    observed = set(grouped)
    missing = sorted(expected - observed)
    unknown = sorted(observed - expected)
    workflows = Counter()
    semantic_statuses = Counter()
    failed_calls = 0
    errors = Counter()
    failure_families = Counter()
    successful_tools: set[str] = set()
    metrics: dict[str, list[float]] = {key: [] for key in METRIC_NAMES}
    protocol_success_metrics: dict[str, list[float]] = {key: [] for key in METRIC_NAMES}
    for receipt in receipts:
        key = receipt_key(receipt)
        semantic = (semantic_by_receipt or {}).get(key, {})
        analysis = analyze_receipt(receipt, semantic)
        workflows[analysis["outcome"]] += 1
        semantic_statuses[analysis["semantic_status"]] += 1
        failed_calls += analysis["failed_calls"]
        errors.update(analysis["errors"])
        failure_families.update(analysis["failure_families"])
        successful_tools.update(analysis["successful_tools"])
        for key, value in analysis["metrics"].items():
            if isinstance(value, (int, float)) and value >= 0:
                metrics[key].append(float(value))
                if analysis["outcome"] == "protocol_success":
                    protocol_success_metrics[key].append(float(value))
    return {
        "receipts": len(receipts),
        "expected_receipts": len(expected),
        "duplicates": [{"workflow": w, "round": r} for w, r in duplicates],
        "missing": [{"workflow": w, "round": r} for w, r in missing],
        "unknown": [{"workflow": w, "round": r} for w, r in unknown],
        "workflow_outcomes": dict(workflows),
        "semantic_statuses": dict(semantic_statuses),
        "failed_calls": failed_calls,
        "error_categories": {f"{code}:{category}": count for (code, category), count in sorted(errors.items())},
        "failure_families": dict(sorted(failure_families.items())),
        "successful_tools": sorted(successful_tools),
        "per_workflow": workflow_metrics(receipts),
        "semantic_coverage": {
            f"{workflow}#round-{round_number}": {
                "statuses": dict(value["statuses"]),
                "semantic_status": "unknown",
                "independent_validation": "not_performed",
                "provider_coverage_statuses": dict(value["provider_coverage_statuses"]),
                "provider_coverage_calls": value.get("provider_coverage_calls", []),
                "limitations": value.get("limitations", []),
            }
            for (workflow, round_number), value in sorted((semantic_by_receipt or {}).items())
        },
        "all_receipt_metrics": {key: metric_stats(values) for key, values in metrics.items()},
        "protocol_success_metrics": {
            key: metric_stats(values) for key, values in protocol_success_metrics.items()
        },
    }


def analyze_receipt(
    receipt: dict[str, Any],
    semantic: dict[str, Any],
) -> dict[str, Any]:
    errors: Counter[tuple[str, str]] = Counter()
    failure_families: Counter[str] = Counter()
    successful_tools: set[str] = set()
    failed_calls = 0

    for call in receipt.get("calls", []):
        if call.get("status") == "success":
            tool = call.get("request", {}).get("params", {}).get("name")
            if tool:
                successful_tools.add(tool)
            continue

        failed_calls += 1
        tool = call.get("request", {}).get("params", {}).get("name", "")
        code, category, _, family = error_info(call.get("error"), str(tool))
        errors[(code, category)] += 1
        failure_families[family] += 1

    semantic_status = semantic.get("status", "semantic_unknown") if semantic else "not_audited"
    return {
        "outcome": outcome(receipt),
        "semantic_status": semantic_status,
        "failed_calls": failed_calls,
        "errors": errors,
        "failure_families": failure_families,
        "successful_tools": successful_tools,
        "metrics": receipt_metric_values(receipt),
    }


def metric_stats(values: list[float]) -> dict[str, Any]:
    if not values:
        return {"count": 0, "median": None, "minimum": None, "maximum": None}
    return {"count": len(values), "median": statistics.median(values), "minimum": min(values), "maximum": max(values)}


def receipt_metric_values(receipt: dict[str, Any]) -> dict[str, float | None]:
    process = receipt.get("process") if isinstance(receipt.get("process"), dict) else {}
    wait4_fields = tuple(
        value
        for value in (
            process.get("wait4_user_cpu_ms"),
            process.get("wait4_system_cpu_ms"),
        )
        if isinstance(value, (int, float))
    )
    wait4_cpu = sum(wait4_fields) if wait4_fields else None
    peak_rss = process.get("sampled_family_peak_rss_bytes")
    return {
        "wall_ms": process.get("wall_ms"),
        "wait4_cpu_ms": wait4_cpu,
        "harness_cpu_ms": receipt.get("harness_cpu_ms"),
        "sampled_family_cpu_ms": process.get("sampled_family_cpu_ms"),
        "sampled_family_peak_rss_mib": peak_rss / (1024 * 1024) if isinstance(peak_rss, (int, float)) else None,
    }


def workflow_metrics(receipts: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    samples: dict[str, dict[str, list[float]]] = {}
    protocol_success_samples: dict[str, dict[str, list[float]]] = {}
    receipt_outcomes: dict[str, Counter[str]] = {}
    call_outcomes: dict[str, Counter[str]] = {}
    for receipt in receipts:
        workflow = str(receipt.get("workflow", {}).get("name", "unknown"))
        metric_samples = samples.setdefault(
            workflow,
            {key: [] for key in METRIC_NAMES},
        )
        successful_samples = protocol_success_samples.setdefault(
            workflow,
            {key: [] for key in METRIC_NAMES},
        )
        receipt_outcomes.setdefault(workflow, Counter())[outcome(receipt)] += 1
        calls = [call for call in receipt.get("calls", []) if isinstance(call, dict)]
        call_statuses = call_outcomes.setdefault(workflow, Counter())
        for call in calls:
            call_statuses[str(call.get("status", "unknown"))] += 1
        for metric, value in receipt_metric_values(receipt).items():
            if isinstance(value, (int, float)) and value >= 0:
                metric_samples[metric].append(float(value))
                if outcome(receipt) == "protocol_success":
                    successful_samples[metric].append(float(value))

    result: dict[str, dict[str, Any]] = {}
    for workflow in sorted(samples | receipt_outcomes.keys() | call_outcomes.keys()):
        result[workflow] = {
            "receipts": sum(receipt_outcomes.get(workflow, Counter()).values()),
            "receipt_outcomes": dict(sorted(receipt_outcomes.get(workflow, Counter()).items())),
            "call_outcomes": dict(sorted(call_outcomes.get(workflow, Counter()).items())),
            "all_receipt_metrics": {
                metric: metric_stats(values)
                for metric, values in sorted(samples.get(workflow, {}).items())
            },
            "protocol_success_metrics": {
                metric: metric_stats(values)
                for metric, values in sorted(protocol_success_samples.get(workflow, {}).items())
            },
        }
    return result


def matched_success_metrics(
    baseline: dict[str, Any],
    current: dict[str, Any],
    eligible_workflows: set[str] | None = None,
) -> dict[str, dict[str, Any]]:
    """Summarize only rounds that succeeded in both comparable receipts."""
    baseline_by_key = {
        receipt_key(item): item
        for item in baseline.get("receipts", [])
        if isinstance(item, dict)
    }
    current_by_key = {
        receipt_key(item): item
        for item in current.get("receipts", [])
        if isinstance(item, dict)
    }
    samples: dict[str, dict[str, dict[str, list[float]]]] = {}
    rounds: dict[str, list[int]] = {}
    for key in sorted(set(baseline_by_key) & set(current_by_key)):
        baseline_receipt = baseline_by_key[key]
        current_receipt = current_by_key[key]
        if (
            outcome(baseline_receipt) != "protocol_success"
            or outcome(current_receipt) != "protocol_success"
        ):
            continue
        workflow, round_number = key
        if eligible_workflows is not None and workflow not in eligible_workflows:
            continue
        rounds.setdefault(workflow, []).append(round_number)
        workflow_samples = samples.setdefault(
            workflow,
            {
                "baseline": {metric: [] for metric in METRIC_NAMES},
                "current": {metric: [] for metric in METRIC_NAMES},
            },
        )
        for side, receipt in (("baseline", baseline_receipt), ("current", current_receipt)):
            for metric, value in receipt_metric_values(receipt).items():
                if isinstance(value, (int, float)) and value >= 0:
                    workflow_samples[side][metric].append(float(value))

    return {
        workflow: {
            "paired_rounds": sorted(rounds[workflow]),
            "baseline": {
                metric: metric_stats(values)
                for metric, values in sorted(values_by_metric["baseline"].items())
            },
            "current": {
                metric: metric_stats(values)
                for metric, values in sorted(values_by_metric["current"].items())
            },
        }
        for workflow, values_by_metric in sorted(samples.items())
    }


def index_task_calls(
    raw: dict[str, Any],
) -> tuple[
    dict[tuple[str, int, str], tuple[str, dict[str, Any], bool]],
    set[tuple[str, int, str]],
]:
    calls: dict[tuple[str, int, str], tuple[str, dict[str, Any], bool]] = {}
    duplicates: set[tuple[str, int, str]] = set()
    for receipt in raw.get("receipts", []):
        if not isinstance(receipt, dict):
            continue
        workflow, round_number = receipt_key(receipt)
        for call in receipt.get("calls", []):
            if not isinstance(call, dict):
                continue
            params = call.get("request", {}).get("params", {})
            key = (workflow, round_number, str(call.get("label", "")))
            if key in calls:
                duplicates.add(key)
                continue
            tool = str(params.get("name", ""))
            arguments = params.get("arguments", {})
            calls[key] = (
                tool,
                arguments,
                has_generated_template_proof(receipt, tool, arguments),
            )
    return calls, duplicates


def expected_export_path(work_dir: Path, workflow: str, round_number: int) -> Path:
    return work_dir / f"{workflow}-round-{round_number:03d}" / "evidence-export.json"


def has_generated_template_proof(
    receipt: dict[str, Any],
    tool: str,
    arguments: Any,
) -> bool:
    """Prove that the receipt plan generated this call's path argument."""
    if not isinstance(arguments, dict) or tool not in {
        "export_evidence_bundle",
        "import_evidence_bundle",
    }:
        return False

    workflow = receipt.get("workflow")
    cases = workflow.get("cases") if isinstance(workflow, dict) else None
    if not isinstance(cases, list):
        return False

    matching_cases = [
        case
        for case in cases
        if isinstance(case, dict) and case.get("name") == tool
    ]
    if len(matching_cases) != 1:
        return False

    template_arguments = matching_cases[0].get("arguments")
    if not isinstance(template_arguments, dict):
        return False
    if template_arguments.get("path") != "$export_path":
        return False
    if set(template_arguments) != set(arguments):
        return False

    return all(
        key == "path" or template_arguments[key] == value
        for key, value in arguments.items()
    )


def is_generated_export_call(
    tool: str,
    arguments: Any,
    workflow: str,
    round_number: int,
    work_dir: Path,
) -> bool:
    if (
        tool not in {"export_evidence_bundle", "import_evidence_bundle"}
        or not isinstance(arguments, dict)
    ):
        return False
    expected_keys = {"path", "overwrite"} if tool == "export_evidence_bundle" else {"path"}
    if set(arguments) != expected_keys:
        return False
    if tool == "export_evidence_bundle" and arguments.get("overwrite") is not False:
        return False
    path = arguments.get("path")
    if not isinstance(path, str):
        return False
    try:
        return Path(path).resolve() == expected_export_path(work_dir, workflow, round_number).resolve()
    except OSError:
        return False


def classify_call_difference(
    left: tuple[str, dict[str, Any], bool],
    right: tuple[str, dict[str, Any], bool],
    workflow: str,
    round_number: int,
    baseline_work_dir: Path | None,
    current_work_dir: Path | None,
) -> str:
    if left[0] != right[0] or left[1] == right[1]:
        return "changed_task_input"
    if (
        baseline_work_dir
        and current_work_dir
        and left[0] == right[0]
        and left[2]
        and right[2]
    ):
        left_is_generated = is_generated_export_call(
            left[0], left[1], workflow, round_number, baseline_work_dir
        )
        right_is_generated = is_generated_export_call(
            right[0], right[1], workflow, round_number, current_work_dir
        )
        if left_is_generated and right_is_generated:
            return "run_scoped_output"
    return "changed_task_input"


def task_input_equivalence(
    baseline: dict[str, Any],
    current: dict[str, Any],
    baseline_work_dir: Path | None,
    current_work_dir: Path | None,
) -> dict[str, Any]:
    """Compare caller inputs while allowing only the plan's generated exports."""
    baseline_calls, baseline_duplicates = index_task_calls(baseline)
    current_calls, current_duplicates = index_task_calls(current)
    differences: list[dict[str, Any]] = []
    for key in sorted(baseline_duplicates | current_duplicates):
        differences.append(
            {
                "workflow": key[0],
                "round": key[1],
                "label": key[2],
                "category": "duplicate_call",
            }
        )
    for key in sorted(set(baseline_calls) | set(current_calls)):
        left, right = baseline_calls.get(key), current_calls.get(key)
        if left is None or right is None:
            differences.append(
                {
                    "workflow": key[0],
                    "round": key[1],
                    "label": key[2],
                    "category": "missing_call",
                }
            )
        elif left != right:
            differences.append(
                {
                    "workflow": key[0],
                    "round": key[1],
                    "label": key[2],
                    "category": classify_call_difference(
                        left,
                        right,
                        key[0],
                        key[1],
                        baseline_work_dir,
                        current_work_dir,
                    ),
                    "baseline": left,
                    "current": right,
                }
            )
    changed_workflows = {
        item["workflow"]
        for item in differences
        if item["category"] != "run_scoped_output"
    }
    observed_workflows = {key[0] for key in set(baseline_calls) & set(current_calls)}
    return {
        "equivalent": not changed_workflows,
        "equivalent_workflows": sorted(observed_workflows - changed_workflows),
        "differences": differences[:50],
        "difference_count": len(differences),
        "unpaired_call_count": len(set(baseline_calls) ^ set(current_calls)),
    }


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def call_identity(raw: dict[str, Any]) -> Counter[tuple[str, int, str, str, str]]:
    result: Counter[tuple[str, int, str, str, str]] = Counter()
    for receipt in raw.get("receipts", []):
        if not isinstance(receipt, dict):
            continue
        workflow, round_number = receipt_key(receipt)
        for call in receipt.get("calls", []):
            if not isinstance(call, dict):
                continue
            tool = call.get("request", {}).get("params", {}).get("name", call.get("method", "unknown"))
            identity = (
                workflow,
                round_number,
                str(call.get("label", "")),
                str(tool),
                str(call.get("status", "unknown")),
            )
            result[identity] += 1
    return result


def structural_call_identity(raw: dict[str, Any]) -> Counter[tuple[str, int, str, str, str]]:
    result: Counter[tuple[str, int, str, str, str]] = Counter()
    for receipt in raw.get("receipts", []):
        if not isinstance(receipt, dict):
            continue
        workflow, round_number = receipt_key(receipt)
        for call in receipt.get("calls", []):
            if not isinstance(call, dict):
                continue
            request = call.get("request") if isinstance(call.get("request"), dict) else {}
            params = request.get("params") if isinstance(request.get("params"), dict) else {}
            tool = params.get("name", call.get("method", "unknown"))
            arguments = params.get("arguments", {})
            result[(workflow, round_number, str(call.get("label", "")), str(tool), canonical_json(arguments))] += 1
    return result


def catalog_identity(raw: dict[str, Any]) -> dict[str, dict[str, Any]]:
    observed: dict[str, dict[str, set[Any]]] = {}
    for receipt in raw.get("receipts", []):
        if not isinstance(receipt, dict):
            continue
        workflow = str(receipt.get("workflow", {}).get("name", "unknown"))
        tools = receipt.get("catalog_tools")
        workflow_catalog = observed.setdefault(workflow, {"sha256": set(), "tools": set()})
        workflow_catalog["sha256"].add(receipt.get("catalog_sha256"))
        if isinstance(tools, list):
            workflow_catalog["tools"].add(canonical_json(sorted(str(tool) for tool in tools)))
        else:
            workflow_catalog["tools"].add(None)
    result: dict[str, dict[str, Any]] = {}
    for workflow, catalog in sorted(observed.items()):
        tool_values = sorted(value for value in catalog["tools"] if isinstance(value, str))
        result[workflow] = {
            "sha256": sorted(value for value in catalog["sha256"] if isinstance(value, str)),
            "missing_sha256": None in catalog["sha256"],
            "tools": [json.loads(value) for value in tool_values],
            "missing_tools": None in catalog["tools"],
        }
    return result


def structural_equivalence(
    baseline: dict[str, Any],
    current: dict[str, Any],
) -> dict[str, Any]:
    mismatches: list[str] = []
    baseline_plan_sha = baseline.get("plan_sha256")
    current_plan_sha = current.get("plan_sha256")
    plan_match = isinstance(baseline_plan_sha, str) and baseline_plan_sha == current_plan_sha
    if not plan_match:
        mismatches.append("plan_sha256")

    baseline_pairs = planned_pairs(baseline)
    current_pairs = planned_pairs(current)
    pair_match = baseline_pairs == current_pairs
    if not pair_match:
        mismatches.append("planned_workflow_rounds")

    baseline_calls = structural_call_identity(baseline)
    current_calls = structural_call_identity(current)
    calls_match = baseline_calls == current_calls
    if not calls_match:
        mismatches.append("call_arguments")

    baseline_catalogs = catalog_identity(baseline)
    current_catalogs = catalog_identity(current)
    catalogs_match = baseline_catalogs == current_catalogs
    if not catalogs_match:
        mismatches.append("catalog")

    return {
        "equivalent": not mismatches,
        "mismatches": mismatches,
        "plan_sha256": {"baseline": baseline_plan_sha, "current": current_plan_sha, "match": plan_match},
        "planned_workflow_rounds": {
            "baseline_count": len(baseline_pairs),
            "current_count": len(current_pairs),
            "baseline_only": [list(pair) for pair in sorted(baseline_pairs - current_pairs)],
            "current_only": [list(pair) for pair in sorted(current_pairs - baseline_pairs)],
            "match": pair_match,
        },
        "call_arguments": {
            "baseline_rows": sum(baseline_calls.values()),
            "current_rows": sum(current_calls.values()),
            "baseline_only_rows": sum((baseline_calls - current_calls).values()),
            "current_only_rows": sum((current_calls - baseline_calls).values()),
            "match": calls_match,
        },
        "catalog": {"baseline": baseline_catalogs, "current": current_catalogs, "match": catalogs_match},
    }


def compare_series(
    name: str,
    baseline: dict[str, Any],
    current: dict[str, Any],
    baseline_work_dir: Path | None = None,
    current_work_dir: Path | None = None,
) -> dict[str, Any]:
    expected = planned_pairs(baseline)
    baseline_summary = receipt_summary(baseline, expected, semantic_coverage(baseline_work_dir))
    current_summary = receipt_summary(current, expected, semantic_coverage(current_work_dir))
    baseline_calls = call_identity(baseline)
    current_calls = call_identity(current)
    structural = structural_equivalence(baseline, current)
    task_inputs = task_input_equivalence(
        baseline,
        current,
        baseline_work_dir,
        current_work_dir,
    )
    return {
        "series": name,
        "structural_equivalence": structural,
        "baseline": baseline_summary,
        "current": current_summary,
        "successful_tools_added": sorted(
            set(current_summary["successful_tools"])
            - set(baseline_summary["successful_tools"])
        ),
        "successful_tools_removed": sorted(
            set(baseline_summary["successful_tools"])
            - set(current_summary["successful_tools"])
        ),
        "call_identity_delta": {
            "baseline_rows": sum(baseline_calls.values()),
            "current_rows": sum(current_calls.values()),
            "same_identity_status_rows": sum((baseline_calls & current_calls).values()),
        },
        "task_input_equivalence": task_inputs,
        "matched_success_metrics": matched_success_metrics(
            baseline,
            current,
            set(task_inputs["equivalent_workflows"]),
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", action="append", type=parse_series, required=True)
    parser.add_argument("--current", action="append", type=parse_series, required=True)
    parser.add_argument("--baseline-work-dir", action="append", type=parse_series, default=[])
    parser.add_argument("--current-work-dir", action="append", type=parse_series, default=[])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    baseline = dict((name, load(path)) for name, path in args.baseline)
    current = dict((name, load(path)) for name, path in args.current)
    baseline_work_dirs = dict(args.baseline_work_dir)
    current_work_dirs = dict(args.current_work_dir)
    names = sorted(set(baseline) | set(current))
    series = []
    for name in names:
        if name not in baseline or name not in current:
            series.append({"series": name, "status": "missing-input"})
        else:
            series.append(
                compare_series(
                    name,
                    baseline[name],
                    current[name],
                    Path(baseline_work_dirs[name]) if name in baseline_work_dirs else None,
                    Path(current_work_dirs[name]) if name in current_work_dirs else None,
                )
            )
    output = {"schema_version": 1, "status": "measured-comparison", "series": series}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
