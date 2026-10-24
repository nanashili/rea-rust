#!/usr/bin/env python3
"""Measure real Java and Rust Ghidra through the frozen public MCP runtimes.

Each invocation gets a new server, analysis session and Rust worker cache. The
target is read, never executed. Full protocol transcripts and decompiled text
remain beside the local receipts, including failed qualification attempts.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import statistics
import time

import run as runtime
from decompile_fixtures import validate_pseudocode_records
from prepare import refuse_live_builds, sha256


runtime.TIMEOUT_SECONDS = 240
PROVIDERS = {"typescript": "ghidra", "native": "ghidra-rust"}


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n")


def normalized(result: dict) -> object:
    evidence = result.get("structuredContent")
    if not isinstance(evidence, dict) or "normalized_result" not in evidence:
        raise AssertionError("tool response has no normalized Evidence result")
    return evidence["normalized_result"]


def verify_inputs(prepared: Path) -> tuple[dict, dict, dict]:
    provenance = json.loads((prepared / "provenance.json").read_text())
    worker = provenance["build"]["executable"]
    if sha256(Path(worker["path"])) != worker["sha256"]:
        raise AssertionError("frozen worker digest changed")

    ghidra = provenance["ghidra"]
    for record in ghidra["manifest"]:
        if sha256(Path(ghidra["install_dir"]) / record["path"]) != record["sha256"]:
            raise AssertionError(f"Ghidra resource changed: {record['path']}")
    launch_java = ghidra["launch_java"]
    if sha256(Path(launch_java["path"])) != launch_java["sha256"]:
        raise AssertionError("Java launch executable changed")

    frozen = Path(provenance["prepared_runtime"]["root"])
    frozen_provenance = json.loads((frozen / "provenance.json").read_text())
    commands = runtime.prepared_commands(frozen, frozen_provenance)
    fixtures = json.loads((prepared / "fixtures/manifest.json").read_text())
    for target in fixtures["targets"].values():
        record = target["binary"]
        if sha256(prepared / "fixtures" / record["path"]) != record["sha256"]:
            raise AssertionError("fixture digest changed")
    return provenance, commands, fixtures


def invocation_command(base: list[str], lane: str, provenance: dict,
                       workspace: Path) -> list[str]:
    settings = {
        "REA_CONFIG": str(workspace / "absent-config.json"),
        "REA_ANALYSIS_PROVIDER": PROVIDERS[lane],
    }
    if lane == "typescript":
        settings.update(
            GHIDRA_INSTALL_DIR=provenance["ghidra"]["install_dir"],
            JAVA_HOME=provenance["ghidra"]["java_home"],
        )
    else:
        settings.update(
            REA_GHIDRA_RUST_ENABLED="true",
            REA_GHIDRA_RUST_WORKER=provenance["build"]["executable"]["path"],
            REA_GHIDRA_RUST_CACHE_DIR=str(workspace / "worker-cache"),
            REA_GHIDRA_RUST_TIMEOUT_MS="240000",
            REA_GHIDRA_RUST_DECOMPILE_THREADS="1",
        )
    return ["/usr/bin/env", *(f"{key}={value}" for key, value in settings.items()), *base, "mcp"]


def selected_functions(target: dict) -> list[dict]:
    return [
        {"name": name, "selector": "0x" + record["address"].removeprefix("0x")}
        for name, record in target["symbols"].items()
    ]


def request_decompilation(session: runtime.McpSession, function: dict,
                          phase: str) -> dict:
    started = time.perf_counter()
    record = {**function, "phase": phase}
    try:
        response = session.call("procedure_pseudo_code", {"procedure": function["selector"]}, phase)
        text = normalized(response)
        if not isinstance(text, str) or not text.strip():
            raise AssertionError("decompiler returned no pseudocode")
        record.update(status="success", pseudocode=text, sha256=runtime.fingerprint(text))
    except Exception as error:
        record.update(status="failure", error=f"{type(error).__name__}: {error}")
    record["wall_ms"] = (time.perf_counter() - started) * 1000
    return record


def decompile_workflow(session: runtime.McpSession, target: dict,
                       binary: Path, provider: str, started: float) -> dict:
    session.call("open_binary", {"path": str(binary), "provider_id": provider}, "open")
    inventory = normalized(session.call("list_procedures", {}, "analyze_and_list"))
    ready_ms = (time.perf_counter() - started) * 1000
    functions = selected_functions(target)
    results = []
    first_result_ms = None
    for index, function in enumerate(functions):
        phase = "first_decompile" if index == 0 else "additional_decompile"
        results.append(request_decompilation(session, function, phase))
        if index == 0:
            first_result_ms = (time.perf_counter() - started) * 1000

    selected_complete_ms = (time.perf_counter() - started) * 1000
    repeats = [request_decompilation(session, functions[0], "repeat_decompile") for _ in range(8)]
    for repeat in repeats:
        if repeat.get("pseudocode") != results[0].get("pseudocode"):
            repeat.update(status="failure", error="repeat changed the returned pseudocode")

    return {
        "ready_ms": ready_ms,
        "first_result_ms": first_result_ms,
        "selected_complete_ms": selected_complete_ms,
        "inventory": inventory,
        "functions": results,
        "repeats": repeats,
    }


def finish_invocation(child: runtime.OwnedChild, session: runtime.McpSession,
                      workspace: Path, opened: bool) -> tuple[dict, list[BaseException]]:
    failures = []
    if opened:
        previous_timeout = runtime.TIMEOUT_SECONDS
        try:
            runtime.TIMEOUT_SECONDS = 15
            session.call("close_binary", {}, "close")
        except BaseException as error:
            failures.append(error)
        finally:
            runtime.TIMEOUT_SECONDS = previous_timeout

    metrics = {}
    try:
        metrics = child.finish(timeout=15)
        if metrics.get("exit_code") != 0 or metrics.get("termination") != "stdin-eof":
            failures.append(RuntimeError(f"server shutdown failed: {metrics}"))
    except BaseException as error:
        failures.append(error)

    for name, value in [("transcript.json", session.transcript), ("phases.json", session.phases)]:
        try:
            write_json(workspace / name, value)
        except BaseException as error:
            failures.append(error)
    try:
        (workspace / "stderr.log").write_bytes(child.stderr)
    except BaseException as error:
        failures.append(error)
    return metrics, failures


def run_invocation(command: list[str], prepared: Path, workspace: Path,
                   lane: str, target_name: str, fixtures: dict) -> dict:
    workspace.mkdir()
    child = runtime.OwnedChild(command, prepared, mcp=True)
    session = runtime.McpSession(child)
    failure = None
    opened = False
    value = {}
    discovery_ms = None
    try:
        tools = session.discover()
        discovery_ms = (time.perf_counter() - child.started) * 1000
        required = {"open_binary", "list_procedures", "procedure_pseudo_code", "close_binary"}
        if not required.issubset({tool["name"] for tool in tools}):
            raise AssertionError("server does not advertise required decompilation tools")
        opened = True
        target = fixtures["targets"][target_name]
        value = decompile_workflow(session, target,
                                  prepared / "fixtures" / target["binary"]["path"],
                                  PROVIDERS[lane], child.started)
    except BaseException as error:
        failure = error
    finally:
        metrics, cleanup_failures = finish_invocation(child, session, workspace, opened)

    try:
        value["quality"] = {"status": "passed", **validate_pseudocode_records(
            value.get("functions", []), fixtures, target_name)}
    except Exception as error:
        value["quality"] = {"status": "failed", "error": f"{type(error).__name__}: {error}"}
    try:
        write_json(workspace / "evidence.json", value)
    except BaseException as error:
        cleanup_failures.append(error)
    if failure is not None:
        for error in cleanup_failures:
            failure.add_note(f"finalization also failed: {error}")
        failure.metrics = metrics
        raise failure
    if cleanup_failures:
        raise BaseExceptionGroup("decompilation finalization failed", cleanup_failures)

    return invocation_metrics(metrics, value, discovery_ms, session, workspace)


def invocation_metrics(metrics: dict, value: dict, discovery_ms: float,
                       session: runtime.McpSession, workspace: Path) -> dict:
    all_results = [*value["functions"], *value["repeats"]]
    complete = (all(result["status"] == "success" for result in all_results)
                and value["quality"]["status"] == "passed")
    return {
        **metrics,
        "status": "success" if complete else "incomplete",
        "quality": value["quality"],
        "discovery_ms": discovery_ms,
        "ready_ms": value["ready_ms"],
        "first_result_ms": value["first_result_ms"],
        "selected_complete_ms": value["selected_complete_ms"],
        "first_decompile_ms": value["functions"][0]["wall_ms"],
        "repeat_median_ms": statistics.median(result["wall_ms"] for result in value["repeats"]),
        "functions": [{key: result[key] for key in result if key != "pseudocode"}
                      for result in value["functions"]],
        "repeats": [{key: result[key] for key in result if key != "pseudocode"}
                    for result in value["repeats"]],
        "phases": session.phases,
        "transcript": str(workspace / "transcript.json"),
        "evidence": str(workspace / "evidence.json"),
        "evidence_sha256": sha256(workspace / "evidence.json"),
    }


def summarize(rows: list[dict]) -> dict:
    summary = {}
    fields = ["wall_ms", "cpu_ms", "sampled_family_peak_rss_bytes", "first_result_ms",
              "selected_complete_ms", "first_decompile_ms", "repeat_median_ms", "ready_ms"]
    for target in sorted({row["target"] for row in rows}):
        summary[target] = {}
        for lane in PROVIDERS:
            selected = [row for row in rows if row["target"] == target and row["lane"] == lane
                        and row["status"] == "success"]
            if selected:
                summary[target][lane] = {
                    "samples": len(selected),
                    **{field: runtime.distribution([row[field] for row in selected]) for field in fields},
                }
    return summary


def new_receipt(prepared: Path, qualification: bool) -> dict:
    return {
        "schema": "rea-ghidra-decompile-benchmark-v1",
        "qualification_only": qualification,
        "started_at_utc": runtime.utc_timestamp(),
        "prepared_provenance_sha256": sha256(prepared / "provenance.json"),
        "fixture_manifest_sha256": sha256(prepared / "fixtures/manifest.json"),
        "harness_sha256": {name: sha256(Path(__file__).parent / name) for name in
                           ["run.py", "prepare.py", "fixtures.py", "run_decompile.py", "prepare_decompile.py", "decompile_fixtures.py"]},
        "cache_policy": "fresh server/session and worker cache each invocation; OS filesystem cache not flushed; eight repeated requests in each live session",
        "cpu_policy": "wait4 root user+system time; includes only descendant CPU attributed by the OS when children are waited, not a separately sampled exact family CPU total",
        "rows": [],
    }


def measure_sample(prepared: Path, output: Path, commands: dict, provenance: dict,
                   fixtures: dict, target: str, sample: int, lanes: list[str]) -> list[dict]:
    rows = []
    for lane in lanes:
        refuse_live_builds()
        workspace = output / f"{target}-{sample}-{lane}"
        command = invocation_command(commands[lane], lane, provenance, workspace)
        row = {"target": target, "sample": sample, "lane": lane, "provider": PROVIDERS[lane],
               "command": command, "load_average_before": os.getloadavg()}
        try:
            row.update(run_invocation(command, prepared, workspace, lane, target, fixtures))
        except Exception as error:
            row.update(getattr(error, "metrics", {}))
            row.update(status="failure", error=f"{type(error).__name__}: {error}")
        rows.append(row)
        print(f"{target} {sample} {lane}: {row['status']}", flush=True)
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepared", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--samples", type=int, default=7)
    parser.add_argument("--target", choices=["small", "gofmt"], action="append")
    parser.add_argument("--qualification", action="store_true")
    args = parser.parse_args()
    if args.samples < 1:
        parser.error("samples must be positive")

    prepared = args.prepared.resolve()
    output = args.output.resolve()
    provenance, commands, fixtures = verify_inputs(prepared)
    output.mkdir()
    document = new_receipt(prepared, args.qualification)

    for sample in range(1, args.samples + 1):
        for target in args.target or ["small", "gofmt"]:
            order = ["typescript", "native"] if sample % 2 else ["native", "typescript"]
            document["rows"].extend(measure_sample(
                prepared, output, commands, provenance, fixtures, target, sample, order))
            document["summary"] = summarize(document["rows"])
            document["finished_at_utc"] = runtime.utc_timestamp()
            write_json(output / "results.json", document)


if __name__ == "__main__":
    main()
