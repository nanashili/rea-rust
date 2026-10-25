#!/usr/bin/env python3
"""Summarize benchmark receipts without copying target content into reports.

The runner deliberately keeps full MCP responses in the work directory.  This
script reads only operation names, status, bounded result counts, and resource
metrics so a public summary cannot accidentally contain application strings or
decompiled source.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--aggregate", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def response_object(call_file: Path) -> dict[str, Any] | None:
    try:
        call = json.loads(call_file.read_text())
        response = call.get("response", {})
        result = response.get("result", {})
        text = "".join(
            item.get("text", "")
            for item in result.get("content", [])
            if item.get("type") == "text"
        )
        value = json.loads(text)
        return value if isinstance(value, dict) else None
    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        return None


def bounded_result_facts(value: dict[str, Any]) -> dict[str, Any]:
    operation = value.get("operation")
    normalized = value.get("normalized_result")
    facts: dict[str, Any] = {"operation": operation}

    if operation == "list_procedures":
        if isinstance(normalized, list):
            facts["procedure_count"] = len(normalized)
        elif value.get("total_items") is not None:
            facts["procedure_count"] = value["total_items"]
        if value.get("total_items") is not None:
            facts["inventory_total_items"] = value["total_items"]
        if value.get("delivery") is not None:
            facts["delivery"] = value["delivery"]
        if value.get("continuation") is not None:
            facts["has_continuation"] = bool(value["continuation"])
    elif operation == "list_strings" and isinstance(normalized, list):
        facts["string_count"] = len(normalized)
    elif operation == "inspect_asset_catalog" and isinstance(normalized, dict):
        facts["record_count"] = len(normalized.get("records") or [])
        facts["total_records"] = normalized.get("total_records")
        facts["truncated"] = normalized.get("truncated")
    elif operation == "inspect_sqlite_database" and isinstance(normalized, dict):
        schema = normalized.get("schema") or {}
        facts["table_count"] = len(schema.get("tables") or [])
        facts["index_count"] = len(schema.get("indexes") or [])
        facts["view_count"] = len(schema.get("views") or [])
        facts["trigger_count"] = len(schema.get("triggers") or [])
    elif operation == "inspect_analysis_view" and isinstance(normalized, dict):
        coverage = normalized.get("coverage") or {}
        facts["coverage"] = {
            key: coverage.get(key)
            for key in ("examined", "total", "status", "exhausted")
            if key in coverage
        }
    elif operation == "inspect_pe_resources" and isinstance(normalized, dict):
        artifact = normalized.get("artifact") or {}
        coverage = normalized.get("coverage") or {}
        facts["format"] = normalized.get("format")
        facts["artifact"] = {
            key: artifact.get(key)
            for key in ("bytes", "sha256")
            if key in artifact
        }
        facts["coverage"] = {
            key: coverage.get(key)
            for key in ("status", "examined_entries", "resources")
            if key in coverage
        }
        facts["resource_count"] = len(normalized.get("resources") or [])
        facts["limitations"] = [
            limitation
            for limitation in normalized.get("limitations", [])
            if isinstance(limitation, str)
        ]
    return facts


def summarize_workflows(receipts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    workflows: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"rounds": 0, "statuses": Counter(), "calls": 0, "operations": Counter()}
    )

    for receipt in receipts:
        workflow = receipt.get("workflow", {}).get("name", "unknown")
        entry = workflows[workflow]
        entry["rounds"] += 1
        entry["statuses"][receipt.get("status", "unknown")] += 1
        entry["calls"] += len(receipt.get("calls", []))
        for call in receipt.get("calls", []):
            request = call.get("request", {})
            name = request.get("params", {}).get("name")
            if name:
                entry["operations"][name] += 1

    workflow_summary: list[dict[str, Any]] = []
    for workflow, entry in sorted(workflows.items()):
        workflow_summary.append(
            {
                "workflow": workflow,
                "rounds": entry["rounds"],
                "statuses": dict(entry["statuses"]),
                "calls": entry["calls"],
                "operations": dict(sorted(entry["operations"].items())),
            }
        )
    return workflow_summary


def collect_bounded_facts(work_dir: Path) -> list[dict[str, Any]]:
    facts: list[dict[str, Any]] = []
    for call_file in sorted(work_dir.glob("**/call-*.json")):
        value = response_object(call_file)
        if value:
            bounded = bounded_result_facts(value)
            if len(bounded) > 1:
                match = re.match(r"^(.*)-round-(\d+)$", call_file.parent.name)
                if match:
                    bounded["workflow"] = match.group(1)
                    bounded["round"] = int(match.group(2))
                else:
                    bounded["workflow"] = call_file.parent.name
                facts.append(bounded)
    return facts


def build_output(
    aggregate: dict[str, Any],
    aggregate_path: Path,
    workflow_summary: list[dict[str, Any]],
    bounded_facts: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    output: dict[str, Any] = {
        "schema_version": 1,
        "source": str(aggregate_path),
        "benchmark": {
            key: aggregate.get(key)
            for key in (
                "plan_sha256",
                "rea_sha256",
                "worker_sha256",
                "platform",
                "machine",
                "rounds",
            )
        },
        "workflow_summary": workflow_summary,
    }
    if bounded_facts is not None:
        output["bounded_result_facts"] = bounded_facts
    return output


def write_output(output_path: Path, output: dict[str, Any]) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n")


def main() -> None:
    args = parse_args()
    aggregate = json.loads(args.aggregate.read_text())
    receipts = aggregate.get("receipts", [])
    workflow_summary = summarize_workflows(receipts)
    bounded_facts = collect_bounded_facts(args.work_dir) if args.work_dir else None
    output = build_output(aggregate, args.aggregate, workflow_summary, bounded_facts)

    write_output(args.output, output)


if __name__ == "__main__":
    main()
