#!/usr/bin/env python3
"""Summarize a completed local REA MCP benchmark.

The runner keeps compact receipts in the aggregate JSON and detailed call
responses in its work directory.  This command deliberately reads only the
aggregate and provenance manifests, so the published report cannot copy
application code or large MCP response bodies into ``docs/benchmarks``.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import re
from pathlib import Path
import statistics
from typing import Any, Iterable

from receipt_utils import compact_text, error_summary


REPORT_SCHEMA_VERSION = 1


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError(f"expected an object in {path}")
    return value


def finite_numbers(values: Iterable[Any]) -> list[float]:
    return [float(value) for value in values if isinstance(value, (int, float)) and math.isfinite(float(value))]


def metric_stats(values: Iterable[Any]) -> dict[str, Any]:
    numbers = finite_numbers(values)
    if not numbers:
        return {"count": 0, "median": None, "minimum": None, "maximum": None}
    return {
        "count": len(numbers),
        "median": statistics.median(numbers),
        "minimum": min(numbers),
        "maximum": max(numbers),
    }


def int_or_none(value: Any) -> int | None:
    return int(value) if isinstance(value, (int, float)) and math.isfinite(float(value)) else None


def sampled_or_none(value: Any) -> float | None:
    """Treat a zero sampled CPU/RSS observation as unobserved."""
    if not isinstance(value, (int, float)) or not math.isfinite(float(value)) or value <= 0:
        return None
    return float(value)


def first_present(mapping: dict[str, Any], *names: str) -> Any:
    for name in names:
        if name in mapping:
            return mapping[name]
    return None


def call_name(call: dict[str, Any]) -> str:
    request = call.get("request")
    if isinstance(request, dict):
        params = request.get("params")
        if isinstance(params, dict) and isinstance(params.get("name"), str):
            return params["name"]
        if isinstance(request.get("method"), str):
            return request["method"]
    return str(call.get("method") or "unknown")


def call_kind(call: dict[str, Any]) -> str:
    name = call_name(call)
    return "discovery" if name in {"initialize", "tools/list", "tools-list"} else "analysis"


def call_error(call: dict[str, Any]) -> tuple[str, str]:
    code, reason = error_summary(call.get("error"))
    return code or "unknown", reason or "call failed without a structured reason"


def call_row(receipt: dict[str, Any], call: dict[str, Any]) -> dict[str, Any]:
    process = receipt.get("process") if isinstance(receipt.get("process"), dict) else {}
    status = str(call.get("status") or "failure")
    error_code, error_reason = call_error(call) if status != "success" else ("", "")
    rss_bytes = int_or_none(call.get("sampled_family_peak_rss_bytes"))
    workflow = receipt.get("workflow", {}).get("name", "unknown")
    label = call.get("label", "unknown")
    return {
        "workflow": workflow,
        "round": receipt.get("round"),
        "round_class": "first-round" if receipt.get("round") == 1 else "later-round",
        "session_repeat_class": session_repeat_class(label),
        "label": label,
        "call_group": f"{workflow}:{label}",
        "tool": call_name(call),
        "kind": call_kind(call),
        "status": status,
        "error_code": error_code,
        "error_reason": error_reason,
        "wall_ms": call.get("wall_ms"),
        "sampled_family_cpu_ms": sampled_or_none(call.get("sampled_family_cpu_ms")),
        "sampled_family_user_cpu_ms": sampled_or_none(call.get("sampled_family_user_cpu_ms")),
        "sampled_family_system_cpu_ms": sampled_or_none(call.get("sampled_family_system_cpu_ms")),
        "peak_rss_mib": rss_bytes / (1024 * 1024) if rss_bytes and rss_bytes > 0 else None,
        "max_processes": call.get("sampled_family_max_processes"),
        "sample_max_gap_ms": call.get("sampled_max_gap_ms"),
        "output_bytes": call.get("output_bytes", 0),
    }


def summarize_receipt(receipt: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    calls = receipt.get("calls") if isinstance(receipt.get("calls"), list) else []
    rows = [call_row(receipt, call) for call in calls if isinstance(call, dict)]
    process = receipt.get("process") if isinstance(receipt.get("process"), dict) else {}
    successful = receipt.get("status") == "success"
    wait4_user = process.get("wait4_user_cpu_ms")
    wait4_system = process.get("wait4_system_cpu_ms")
    wait4_cpu = None
    if isinstance(wait4_user, (int, float)) or isinstance(wait4_system, (int, float)):
        wait4_cpu = sum(value for value in (wait4_user, wait4_system) if isinstance(value, (int, float)))
    return {
        "workflow": receipt.get("workflow", {}).get("name", "unknown"),
        "round": receipt.get("round"),
        "round_class": "first-round" if receipt.get("round") == 1 else "later-round",
        "started_at_utc": receipt.get("started_at_utc"),
        "ended_at_utc": receipt.get("ended_at_utc"),
        "status": "success" if successful else "failure",
        "error": compact_text(receipt.get("error")) if receipt.get("error") else None,
        "wall_ms": process.get("wall_ms"),
        "wait4_user_cpu_ms": process.get("wait4_user_cpu_ms"),
        "wait4_system_cpu_ms": process.get("wait4_system_cpu_ms"),
        "wait4_cpu_ms": wait4_cpu,
        "harness_cpu_ms": receipt.get("harness_cpu_ms"),
        "wait4_major_faults": first_present(process, "wait4_major_faults", "wait4_majflt", "wait4_ru_majflt", "ru_majflt"),
        "wait4_minor_faults": first_present(process, "wait4_minor_faults", "wait4_minflt", "wait4_ru_minflt", "ru_minflt"),
        "wait4_block_input": first_present(process, "wait4_block_input", "wait4_inblock", "wait4_ru_inblock", "ru_inblock"),
        "wait4_block_output": first_present(process, "wait4_block_output", "wait4_oublock", "wait4_ru_oublock", "ru_oublock"),
        "wait4_voluntary_context_switches": first_present(process, "wait4_voluntary_context_switches", "wait4_ru_nvcsw", "wait4_nvcsw", "ru_nvcsw"),
        "wait4_involuntary_context_switches": first_present(process, "wait4_involuntary_context_switches", "wait4_ru_nivcsw", "wait4_nivcsw", "ru_nivcsw"),
        "wait4_maxrss_mib": (process.get("wait4_maxrss") or 0) / (1024 * 1024) or None,
        "sampled_family_cpu_ms": sampled_or_none(process.get("sampled_family_cpu_ms")),
        "sampled_family_user_cpu_ms": sampled_or_none(process.get("sampled_family_user_cpu_ms")),
        "sampled_family_system_cpu_ms": sampled_or_none(process.get("sampled_family_system_cpu_ms")),
        "sampled_family_peak_rss_mib": sampled_or_none(process.get("sampled_family_peak_rss_bytes")) / (1024 * 1024) if sampled_or_none(process.get("sampled_family_peak_rss_bytes")) is not None else None,
        "sampled_family_max_processes": process.get("sampled_family_max_processes"),
        "sampled_max_gap_ms": process.get("sampled_max_gap_ms"),
        "output_bytes": sum(int(call.get("output_bytes", 0) or 0) for call in calls if isinstance(call, dict)),
        "call_count": len(rows),
        "successful_call_count": sum(row["status"] == "success" for row in rows),
        "failed_call_count": sum(row["status"] != "success" for row in rows),
    }, rows


def group_summary(rows: list[dict[str, Any]], key: str) -> list[dict[str, Any]]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        groups.setdefault(str(row.get(key, "unknown")), []).append(row)
    result = []
    for name, group in sorted(groups.items()):
        result.append({
            key: name,
            "samples": len(group),
            "successes": sum(row["status"] == "success" for row in group),
            "failures": sum(row["status"] != "success" for row in group),
            "wall_ms": metric_stats(row.get("wall_ms") for row in group),
            "sampled_family_cpu_ms": metric_stats(row.get("sampled_family_cpu_ms") for row in group),
            "peak_rss_mib": metric_stats(row.get("peak_rss_mib") for row in group),
            "output_bytes": metric_stats(row.get("output_bytes") for row in group),
            "error_codes": sorted({row.get("error_code", "unknown") for row in group if row["status"] != "success"}),
        })
    return result


def provenance_summary(before: dict[str, Any] | None, after: dict[str, Any] | None, raw: dict[str, Any]) -> dict[str, Any]:
    warnings: list[str] = []
    if before is None or after is None:
        warnings.append("before/after provenance was not supplied")
    files_before = {item.get("resolved_path", item.get("path")): item for item in (before or {}).get("selected_files_before", []) if isinstance(item, dict)}
    files_after = {item.get("resolved_path", item.get("path")): item for item in (after or {}).get("selected_files_after", []) if isinstance(item, dict)}
    changed: list[str] = []
    changed_details: list[dict[str, Any]] = []
    for path in sorted(set(files_before) | set(files_after)):
        left, right = files_before.get(path), files_after.get(path)
        if not left or not right or left.get("sha256") != right.get("sha256") or left.get("device") != right.get("device") or left.get("inode") != right.get("inode"):
            changed.append(str(path))
            changed_details.append({
                "path": path,
                "before": {key: left.get(key) for key in ("sha256", "device", "inode", "size_bytes")} if left else None,
                "after": {key: right.get(key) for key in ("sha256", "device", "inode", "size_bytes")} if right else None,
            })
    if changed:
        warnings.append("selected artifacts changed between provenance captures")
    all_file_observations = [*files_before.values(), *files_after.values()]
    if any(item.get("changed_during_read") for item in all_file_observations if isinstance(item, dict)):
        warnings.append("an artifact changed while it was hashed")
    host = (before or {}).get("host") or (after or {}).get("host")
    tooling_paths = {
        name: (before or {}).get(f"{name}_path") or (after or {}).get(f"{name}_path")
        for name in ("plan", "rea", "worker", "runner")
    }
    tooling: dict[str, Any] = {}
    for name, path_value in tooling_paths.items():
        if not path_value:
            continue
        left = files_before.get(str(Path(path_value).resolve())) or files_before.get(str(path_value))
        right = files_after.get(str(Path(path_value).resolve())) or files_after.get(str(path_value))
        tooling[name] = {
            "path": path_value,
            "before": {key: left.get(key) for key in ("sha256", "device", "inode", "size_bytes")} if left else None,
            "after": {key: right.get(key) for key in ("sha256", "device", "inode", "size_bytes")} if right else None,
        }
        if left and right and (left.get("sha256"), left.get("device"), left.get("inode")) != (right.get("sha256"), right.get("device"), right.get("inode")):
            warnings.append(f"{name} tooling file changed between provenance captures")
    return {
        "plan_sha256": raw.get("plan_sha256"),
        "plan_sha256_kind": "canonical JSON plan digest from the benchmark runner",
        "tooling": tooling,
        "rea_sha256": raw.get("rea_sha256"),
        "worker_sha256": raw.get("worker_sha256"),
        "host": host,
        "changed_selected_paths": changed,
        "changed_file_details": changed_details,
        "warnings": warnings,
    }


def session_repeat_class(label: Any) -> str:
    """Classify repeated labels within one retained MCP session only."""
    match = re.search(r"#(\d+)$", str(label))
    if match and int(match.group(1)) > 1:
        return "retained-session-repeat"
    return "session-first-call"


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(
            stream,
            fieldnames=fields,
            extrasaction="ignore",
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(rows)


def sample_coverage(raw: dict[str, Any], receipts: list[dict[str, Any]]) -> dict[str, Any]:
    plan = next((receipt.get("plan") for receipt in receipts if isinstance(receipt.get("plan"), dict)), {})
    planned = [workflow.get("name") for workflow in plan.get("workflows", []) if isinstance(workflow, dict) and isinstance(workflow.get("name"), str)]
    rounds = raw.get("rounds") if isinstance(raw.get("rounds"), int) else None
    expected = len(planned) * rounds if rounds is not None else None
    pairs = [(receipt.get("workflow", {}).get("name"), receipt.get("round")) for receipt in receipts]
    counts: dict[tuple[Any, Any], int] = {}
    for pair in pairs:
        counts[pair] = counts.get(pair, 0) + 1
    duplicates = [{"workflow": pair[0], "round": pair[1], "count": count} for pair, count in counts.items() if count > 1]
    expected_pairs = {(name, round_number) for name in planned for round_number in range(1, (rounds or 0) + 1)}
    actual_pairs = set(pairs)
    missing = [{"workflow": pair[0], "round": pair[1]} for pair in sorted(expected_pairs - actual_pairs, key=str)]
    unknown = sorted({str(pair[0]) for pair in actual_pairs if pair[0] not in planned})
    warnings = []
    if expected is not None and len(receipts) != expected:
        warnings.append(f"expected {expected} workflow-round samples but found {len(receipts)}")
    if duplicates:
        warnings.append("duplicate workflow-round samples are present")
    if missing:
        warnings.append("workflow-round samples are missing")
    if unknown:
        warnings.append("receipts contain workflows absent from the plan")
    return {
        "planned_workflows": planned,
        "rounds": rounds,
        "expected_samples": expected,
        "actual_samples": len(receipts),
        "unique_workflow_rounds": len(actual_pairs),
        "duplicates": duplicates,
        "missing": missing,
        "unknown_workflows": unknown,
        "warnings": warnings,
    }


def markdown_report(summary: dict[str, Any], raw_path: Path, output_dir: Path) -> str:
    readme_link = os.path.relpath(
        Path(__file__).resolve().with_name("README.md"),
        output_dir.resolve(),
    )
    lines = [
        "# Local application benchmark",
        "",
        f"Native REA MCP benchmark on `{summary['provenance'].get('host', {}).get('platform', 'unknown host')}`. Status: **{summary['status']['label']}**.",
        "This report measures a fresh REA process with isolated REA/provider-cache directories for every workflow sample. Round 1 is the first-round sample; later rounds are later-round samples with a new process. Only repeated labels such as `#2` within one workflow are retained-session repeats. The OS filesystem cache is uncontrolled, so these results make no cold-OS claim.",
        "",
        "## Results",
        "",
        "| Workflow | Samples | Passed | Failed | Wall median [min–max] (ms) | wait4 CPU median (ms) | Harness CPU median (ms) | Family CPU median (ms) | Peak family RSS median (MiB) |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for item in summary["workflows"]:
        wall = item["wall_ms"]
        lines.append(f"| `{item['workflow']}` | {item['samples']} | {item['successes']} | {item['failures']} | {fmt(wall['median'])} [{fmt(wall['minimum'])}–{fmt(wall['maximum'])}] | {fmt(item['wait4_cpu_ms']['median'])} | {fmt(item['harness_cpu_ms']['median'])} | {fmt(item['sampled_family_cpu_ms']['median'])} | {fmt(item['sampled_family_peak_rss_mib']['median'])} |")
    timing = {item["kind"]: item for item in summary["call_timing"]}
    lines += [
        "",
        "The table includes every attempted workflow, including failed processes, so resource costs are visible even when a workflow did not complete. Use the `successful` metrics in `summary.json` for performance ranking; never rank a failed sample as a successful result.",
        f"Run totals: {summary['status']['samples']} workflow samples ({summary['status']['successes']} successful, {summary['status']['failures']} failed) and {summary['status']['calls']} calls ({summary['status']['successful_calls']} successful, {summary['status']['failed_calls']} failed).",
        "",
        f"Coverage: {summary['coverage']['actual_samples']} receipts, {summary['coverage']['unique_workflow_rounds']} unique workflow/round pairs; expected {summary['coverage']['expected_samples'] if summary['coverage']['expected_samples'] is not None else 'unknown'}. {', '.join(summary['coverage']['warnings']) if summary['coverage']['warnings'] else 'No missing, duplicate, or unknown workflow-round samples.'}",
        "",
        f"Call wall-time medians: discovery {fmt(timing['discovery']['wall_ms']['median'])} ms; analysis {fmt(timing['analysis']['wall_ms']['median'])} ms.",
        f"Measured `tools/list` response bytes: median {fmt(summary['catalog_output_bytes']['median'])}, minimum {fmt(summary['catalog_output_bytes']['minimum'])}, maximum {fmt(summary['catalog_output_bytes']['maximum'])}.",
        "",
        "## Accounting and limits",
        "",
        "`wait4` user/system CPU is OS accounting and may include waited descendants. Family CPU and RSS are recursive 5 ms `psutil` observations, lower bounds that can miss short-lived children. A zero sampled value is reported as unobserved. Host background load was not isolated. MCP catalog response bytes are measured per discovery call and included in discovery time; they are not a fixed estimate.",
        "",
        "This is a native-only installed-application benchmark. Targets are selected executables and artifacts, not a recursive analysis of each whole application bundle. It contains no fresh TypeScript comparison and does not claim unmeasured CPU, I/O, energy, or token costs. Raw response bodies and application code stay in the local runner work directory.",
        "",
        "## Reproduce",
        "",
        f"Use the plan and runner documented in [`scripts/benchmarks/README.md`]({readme_link}), then summarize with `python3 scripts/benchmarks/summarize.py --raw {raw_path} --before <before.json> --after <after.json> --output-dir {output_dir}`.",
        "",
        f"Run UTC: {summary.get('started_at_utc') or 'unknown'} to {summary.get('ended_at_utc') or 'unknown'}. The aggregate plan hash is a canonical JSON digest; provenance manifests record the plan file-byte hash. Provenance warnings: {', '.join(summary['provenance']['warnings']) if summary['provenance']['warnings'] else 'none'}.",
        "",
        "Generated files: [`summary.json`](summary.json), [`workflows.csv`](workflows.csv), and [`calls.csv`](calls.csv).",
        "",
    ]
    return "\n".join(lines)


def fmt(value: Any) -> str:
    return "—" if value is None else f"{float(value):.2f}"


def collect_receipt_rows(receipts: list[Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    workflow_samples: list[dict[str, Any]] = []
    call_rows: list[dict[str, Any]] = []
    for receipt in receipts:
        if not isinstance(receipt, dict):
            continue
        sample, rows = summarize_receipt(receipt)
        workflow_samples.append(sample)
        call_rows.extend(rows)
    return workflow_samples, call_rows


def add_workflow_metrics(
    workflow_groups: list[dict[str, Any]],
    workflow_samples: list[dict[str, Any]],
    call_rows: list[dict[str, Any]],
) -> None:
    workflow_error_codes: dict[str, set[str]] = {}
    for row in call_rows:
        if row["status"] != "success":
            workflow_error_codes.setdefault(row["workflow"], set()).add(row["error_code"])

    for item in workflow_groups:
        group = [sample for sample in workflow_samples if sample["workflow"] == item["workflow"]]
        item["sample_details"] = group
        item["error_codes"] = sorted(workflow_error_codes.get(item["workflow"], set()))
        successful_group = [sample for sample in group if sample["status"] == "success"]
        item["successful"] = {
            "samples": len(successful_group),
            "wall_ms": metric_stats(sample.get("wall_ms") for sample in successful_group),
            "wait4_cpu_ms": metric_stats(sample.get("wait4_cpu_ms") for sample in successful_group),
            "harness_cpu_ms": metric_stats(sample.get("harness_cpu_ms") for sample in successful_group),
            "sampled_family_cpu_ms": metric_stats(sample.get("sampled_family_cpu_ms") for sample in successful_group),
            "sampled_family_peak_rss_mib": metric_stats(sample.get("sampled_family_peak_rss_mib") for sample in successful_group),
        }
        item["sampled_family_peak_rss_mib"] = metric_stats(sample.get("sampled_family_peak_rss_mib") for sample in group)
        item["wait4_cpu_ms"] = metric_stats(sample.get("wait4_cpu_ms") for sample in group)
        item["sampled_family_max_processes"] = metric_stats(sample.get("sampled_family_max_processes") for sample in group)
        item["sampled_max_gap_ms"] = metric_stats(sample.get("sampled_max_gap_ms") for sample in group)
        for metric in (
            "harness_cpu_ms",
            "wait4_major_faults",
            "wait4_minor_faults",
            "wait4_block_input",
            "wait4_block_output",
            "wait4_voluntary_context_switches",
            "wait4_involuntary_context_switches",
        ):
            item[metric] = metric_stats(sample.get(metric) for sample in group)


def build_summary(
    raw: dict[str, Any],
    raw_path: Path,
    before: dict[str, Any] | None,
    after: dict[str, Any] | None,
    workflow_samples: list[dict[str, Any]],
    call_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    receipts = [receipt for receipt in raw.get("receipts", []) if isinstance(receipt, dict)]
    workflow_groups = group_summary(workflow_samples, "workflow")
    add_workflow_metrics(workflow_groups, workflow_samples, call_rows)

    success_count = sum(item["status"] == "success" for item in workflow_samples)
    failure_count = sum(item["status"] != "success" for item in workflow_samples)
    run_status = "unknown" if not workflow_samples else "complete" if failure_count == 0 else "failed" if success_count == 0 else "partial"
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "source_raw": str(raw_path),
        "plan_sha256": raw.get("plan_sha256"),
        "rounds": raw.get("rounds"),
        "started_at_utc": raw.get("started_at_utc") or next((item.get("started_at_utc") for item in workflow_samples if item.get("started_at_utc")), None),
        "ended_at_utc": raw.get("ended_at_utc") or next((item.get("ended_at_utc") for item in reversed(workflow_samples) if item.get("ended_at_utc")), None),
        "scope": "native-only installed-application MCP benchmark",
        "provenance": provenance_summary(before, after, raw),
        "coverage": sample_coverage(raw, receipts),
        "status": {
            "label": run_status,
            "samples": len(workflow_samples),
            "successes": success_count,
            "failures": failure_count,
            "calls": len(call_rows),
            "successful_calls": sum(row["status"] == "success" for row in call_rows),
            "failed_calls": sum(row["status"] != "success" for row in call_rows),
        },
        "workflows": workflow_groups,
        "call_timing": [
            {"kind": kind, "wall_ms": metric_stats(row.get("wall_ms") for row in call_rows if row.get("kind") == kind), "output_bytes": metric_stats(row.get("output_bytes") for row in call_rows if row.get("kind") == kind)}
            for kind in ("discovery", "analysis")
        ],
        "catalog_output_bytes": metric_stats(row.get("output_bytes") for row in call_rows if row.get("tool") in {"tools/list", "tools-list"}),
        "calls": group_summary(call_rows, "call_group"),
    }

def write_outputs(
    output_dir: Path,
    summary: dict[str, Any],
    raw_path: Path,
    workflow_samples: list[dict[str, Any]],
    call_rows: list[dict[str, Any]],
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    workflow_fields = list(workflow_samples[0].keys()) if workflow_samples else ["workflow"]
    call_fields = list(call_rows[0].keys()) if call_rows else ["workflow", "tool"]
    write_csv(output_dir / "workflows.csv", workflow_samples, workflow_fields)
    write_csv(output_dir / "calls.csv", call_rows, call_fields)
    report = markdown_report(summary, raw_path, output_dir).rstrip("\n") + "\n"
    (output_dir / "report.md").write_text(report)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", required=True, type=Path)
    parser.add_argument("--before", type=Path)
    parser.add_argument("--after", type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()

    raw = load_json(args.raw)
    before = load_json(args.before) if args.before else None
    after = load_json(args.after) if args.after else None
    receipts = raw.get("receipts")
    if not isinstance(receipts, list):
        raise ValueError("raw aggregate has no receipts array")

    workflow_samples, call_rows = collect_receipt_rows(receipts)
    summary = build_summary(raw, args.raw, before, after, workflow_samples, call_rows)
    write_outputs(args.output_dir, summary, args.raw, workflow_samples, call_rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
