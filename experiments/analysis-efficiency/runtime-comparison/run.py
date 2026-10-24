#!/usr/bin/env python3
"""Compare frozen REA runtimes through their public CLI and stdio MCP adapters.

Only this runner's children are sampled or stopped. No target fixture is executed.
Resource counters cover the server. MCP process wall time includes live transport,
response handling and fixture checks; CLI output parsing happens after the child
exits. Raw protocol transcripts stay beside the prepared inputs.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
import platform
import queue
import signal
import statistics
import subprocess
import threading
import time
from pathlib import Path

import psutil

from fixtures import create_fixtures, validate_evidence
from prepare import manifest_digest, refuse_live_builds, sha256


TIMEOUT_SECONDS = 60
SAMPLE_INTERVAL_SECONDS = 0.005


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def fingerprint(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def load_fixtures(prepared: Path, gofmt: Path) -> dict:
    fixture_dir = prepared / "fixtures-v3"
    if fixture_dir.exists():
        fixture_manifest = json.loads((fixture_dir / "manifest.json").read_text())
        fixtures = {"manifest": fixture_manifest, "paths": {
            key: fixture_dir / fixture_manifest[key]["path"]
            for key in ["rust_small", "rust_stress", "sqlite", "gofmt"]
        }}
    else:
        fixtures = create_fixtures(fixture_dir, gofmt)
        (fixture_dir / "manifest.json").write_text(
            json.dumps(fixtures["manifest"], indent=2) + "\n"
        )
    for key, path in fixtures["paths"].items():
        if sha256(path) != fixtures["manifest"][key]["sha256"]:
            raise AssertionError(f"fixture digest changed: {key}")
    return fixtures


def define_tasks(fixtures: dict) -> dict[str, list[str]]:
    paths = fixtures["paths"]
    return {
        "version": ["--version"],
        "inspect_rust_small": ["inspect-rust-binary", str(paths["rust_small"]), "--format", "json"],
        "inspect_rust_stress": ["inspect-rust-binary", str(paths["rust_stress"]), "--format", "json"],
        "inspect_go_binary": ["inspect-go-binary", str(paths["gofmt"]), "--format", "json"],
        "catalog": ["mcp"],
        "retained_session": ["mcp"],
    }


def append_receipt(document: dict, receipt: Path) -> None:
    receipt.write_text(json.dumps(document, indent=2) + "\n")


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def harness_digests() -> dict[str, str]:
    root = Path(__file__).resolve().parent
    return {
        name: sha256(root / name)
        for name in ["prepare.py", "fixtures.py", "run.py"]
    }


def normalize_maxrss(value: int) -> int:
    """Return ru_maxrss in bytes on both macOS (bytes) and Linux (KiB)."""
    return value if platform.system() == "Darwin" else value * 1024


class FamilySampler:
    """Sample concurrent RSS; this is a lower bound, not a kernel family peak."""

    def __init__(self, pid: int):
        self.root = psutil.Process(pid)
        self.stop = threading.Event()
        self.peak_bytes = 0
        self.max_processes = 0
        self.samples = 0
        self.max_gap_seconds = 0.0
        self.last_sample = time.perf_counter()
        self.thread = threading.Thread(target=self.collect, daemon=True)
        self.thread.start()

    def collect(self) -> None:
        while not self.stop.is_set():
            now = time.perf_counter()
            self.max_gap_seconds = max(self.max_gap_seconds, now - self.last_sample)
            self.last_sample = now
            try:
                processes = [self.root, *self.root.children(recursive=True)]
            except psutil.Error:
                processes = []

            resident = 0
            observed = 0
            for process in processes:
                try:
                    resident += process.memory_info().rss
                    observed += 1
                except psutil.Error:
                    continue

            self.peak_bytes = max(self.peak_bytes, resident)
            self.max_processes = max(self.max_processes, observed)
            self.samples += 1
            self.stop.wait(SAMPLE_INTERVAL_SECONDS)

    def finish(self) -> dict[str, object]:
        self.stop.set()
        self.thread.join()
        return {
            "sampled_family_peak_rss_bytes": self.peak_bytes,
            "max_observed_family_processes": self.max_processes,
            "rss_samples": self.samples,
            "max_sampling_gap_ms": self.max_gap_seconds * 1000,
        }


class OwnedChild:
    """Own pipes, the process group, sampling and the one wait4 completion."""

    def __init__(self, command: list[str], cwd: Path, *, mcp: bool):
        self.started = time.perf_counter()
        environment = os.environ.copy()
        self.had_rea_config = "REA_CONFIG" in environment
        environment["LC_ALL"] = "C"
        self.process = subprocess.Popen(
            command,
            cwd=cwd,
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        self.sampler = FamilySampler(self.process.pid)
        self.messages: queue.Queue[bytes] = queue.Queue()
        self.stdout = bytearray()
        self.stderr = bytearray()
        self.readers = [
            threading.Thread(target=self.read_stdout, args=(mcp,), daemon=True),
            threading.Thread(target=self.read_stderr, daemon=True),
        ]
        for reader in self.readers:
            reader.start()
        self.finished = False
        self.metrics: dict[str, object] = {}
        self.wait_status: tuple[int, object] | None = None
        self.environment_policy = "inherit ambient environment; force LC_ALL=C"

    def check_exited(self) -> bool:
        if self.wait_status is not None:
            return True
        pid, status, usage = os.wait4(self.process.pid, os.WNOHANG)
        if pid:
            self.wait_status = (status, usage)
            return True
        return False

    def read_stdout(self, mcp: bool) -> None:
        assert self.process.stdout is not None
        if mcp:
            for line in self.process.stdout:
                self.messages.put(line)
        else:
            self.stdout.extend(self.process.stdout.read())

    def read_stderr(self) -> None:
        assert self.process.stderr is not None
        self.stderr.extend(self.process.stderr.read())

    def finish(self, timeout: float = TIMEOUT_SECONDS) -> dict[str, object]:
        if self.finished:
            return self.metrics
        assert self.process.stdin is not None
        try:
            self.process.stdin.close()
        except BrokenPipeError:
            pass
        deadline = time.monotonic() + timeout
        termination = "stdin-eof"
        while True:
            if self.wait_status is not None:
                status, usage = self.wait_status
                break
            pid, status, usage = os.wait4(self.process.pid, os.WNOHANG)
            if pid:
                self.wait_status = (status, usage)
                break
            if time.monotonic() >= deadline:
                # The fresh process group belongs solely to this invocation.
                try:
                    os.killpg(self.process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                pid, status, usage = os.wait4(self.process.pid, 0)
                self.wait_status = (status, usage)
                termination = "owned-group-timeout-kill"
                break
            time.sleep(0.0005)

        elapsed = time.perf_counter() - self.started
        self.process.returncode = os.waitstatus_to_exitcode(status)
        reader_failure = None
        for reader in self.readers:
            reader.join(timeout=5)
            if reader.is_alive():
                reader_failure = RuntimeError("owned child exited with an undrained pipe")

        self.metrics = {
            "wall_ms": elapsed * 1000,
            "user_cpu_ms": usage.ru_utime * 1000,
            "system_cpu_ms": usage.ru_stime * 1000,
            "cpu_ms": (usage.ru_utime + usage.ru_stime) * 1000,
            "root_wait4_maxrss_bytes": normalize_maxrss(usage.ru_maxrss),
            "exit_code": self.process.returncode,
            "termination": termination,
            "environment_policy": self.environment_policy,
            "rea_config_present": self.had_rea_config,
            **self.sampler.finish(),
        }
        self.finished = True
        if reader_failure:
            raise reader_failure
        return self.metrics


class McpSession:
    def __init__(self, child: OwnedChild):
        self.child = child
        self.ident = 0
        self.transcript: list[dict[str, object]] = []
        self.phases: list[dict[str, object]] = []

    def request(self, method: str, params: dict, label: str) -> dict:
        self.ident += 1
        message = {"jsonrpc": "2.0", "id": self.ident, "method": method, "params": params}
        started = time.perf_counter()
        self.write(message)
        deadline = time.monotonic() + TIMEOUT_SECONDS
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"{label}: timed out waiting for JSON-RPC response")
            try:
                raw = self.child.messages.get(timeout=min(0.2, remaining))
            except queue.Empty:
                if self.child.check_exited():
                    raise RuntimeError(f"{label}: child exited before replying")
                continue
            reply = json.loads(raw)
            self.transcript.append({"direction": "output", "message": reply})
            if reply.get("id") == self.ident:
                break
        elapsed_ms = (time.perf_counter() - started) * 1000
        if "error" in reply:
            raise RuntimeError(f"{label}: JSON-RPC error: {reply['error']}")
        result = reply["result"]
        if result.get("isError"):
            raise RuntimeError(f"{label}: tool failure: {str(result)[:1000]}")
        self.phases.append({"phase": label, "wall_ms": elapsed_ms,
                            "response_sha256": fingerprint(result)})
        return result

    def write(self, message: dict) -> None:
        self.transcript.append({"direction": "input", "message": message})
        assert self.child.process.stdin is not None
        try:
            self.child.process.stdin.write(json.dumps(message, separators=(",", ":")).encode() + b"\n")
            self.child.process.stdin.flush()
        except BrokenPipeError as error:
            raise RuntimeError("MCP child closed stdin") from error

    def discover(self) -> list[dict]:
        self.request("initialize", {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "rea-runtime-benchmark", "version": "1"},
        }, "initialize")
        self.write({"jsonrpc": "2.0", "method": "notifications/initialized"})
        tools = []
        params = {}
        while True:
            page = self.request("tools/list", params, "catalog")
            tools.extend(page["tools"])
            if not page.get("nextCursor"):
                return tools
            params = {"cursor": page["nextCursor"]}

    def call(self, name: str, arguments: dict, label: str) -> dict:
        return self.request("tools/call", {"name": name, "arguments": arguments}, label)


def run_cli(command: list[str], cwd: Path, task: str, fixtures: dict) -> tuple[dict, object]:
    child = OwnedChild(command, cwd, mcp=False)
    metrics = child.finish()
    if metrics["exit_code"]:
        error = RuntimeError(f"CLI exit {metrics['exit_code']}: {child.stderr.decode(errors='replace')[:1000]}")
        error.metrics = metrics
        raise error
    output = bytes(child.stdout)
    try:
        if task == "version":
            value = output.decode().strip()
            if value != "6.7.0":
                raise AssertionError(f"unexpected version: {value}")
        else:
            value = json.loads(output)
            validate_evidence(task, value, fixtures)
    except Exception as error:
        error.metrics = metrics
        raise
    return {**metrics, "output_bytes": len(output), "output_sha256": hashlib.sha256(output).hexdigest()}, value


def retained_workflow(session: McpSession, fixtures: dict, export_path: Path) -> list[dict]:
    """Read real Go metadata, repeat it, then retrieve and export retained proof."""
    arguments = {"path": str(fixtures["paths"]["gofmt"])}
    results = []
    for index in range(9):
        result = session.call("inspect_go_binary", arguments,
                              "first_inspection" if index == 0 else "repeated_inspection")
        evidence = result["structuredContent"]
        validate_evidence("inspect_go_binary", evidence, fixtures)
        results.append(result)

    evidence_id = results[0]["structuredContent"]["evidence_id"]
    for detail in ["summary", "complete"]:
        arguments = {"detail": detail}
        if detail == "summary":
            arguments["filters"] = {"evidence_id": evidence_id}
        result = session.call("get_evidence_bundle", arguments, "retained_" + detail)
        results.append(result)
    result = session.call("export_evidence_bundle", {"path": str(export_path)}, "export")
    results.append(result)
    exported = json.loads(export_path.read_bytes())
    if len(exported["records"]) != 1:
        raise AssertionError("repeated inspection failed to retain exactly one record")
    if exported["records"][0] != results[0]["structuredContent"]:
        raise AssertionError("export lost complete retained Evidence")
    export_path.unlink(missing_ok=True)
    return [*results, exported]


def run_mcp(command: list[str], cwd: Path, task: str, fixtures: dict,
            transcript: Path, export_path: Path) -> tuple[dict, object]:
    child = OwnedChild(command, cwd, mcp=True)
    session = McpSession(child)
    tools = []
    discovery_ms = None
    results = []
    metrics = {}
    failure = None
    try:
        tools = session.discover()
        discovery_ms = (time.perf_counter() - child.started) * 1000
        results = [] if task == "catalog" else retained_workflow(session, fixtures, export_path)
    except Exception as error:
        failure = error
    finally:
        cleanup_failure = None
        transcript_failure = None
        try:
            metrics = child.finish(timeout=5)
        except Exception as error:
            cleanup_failure = error
        try:
            transcript.write_text(json.dumps(session.transcript, separators=(",", ":")) + "\n")
        except Exception as error:
            transcript_failure = error

        finalization_failures = [
            error for error in [cleanup_failure, transcript_failure]
            if error is not None
        ]
        if failure is None and finalization_failures:
            raise ExceptionGroup("MCP finalization failed", finalization_failures)
        if failure is not None:
            for error in finalization_failures:
                failure.add_note(f"MCP finalization also failed: {error}")
    if failure is not None:
        failure.metrics = metrics
        raise failure
    if metrics["exit_code"]:
        raise RuntimeError(f"MCP shutdown failed: {metrics}; {child.stderr.decode(errors='replace')[:1000]}")
    metrics = {
        **metrics, "discovery_ms": discovery_ms, "phases": session.phases,
        "catalog_tools": len(tools), "catalog_sha256": fingerprint(tools),
        "catalog_names": sorted(tool["name"] for tool in tools),
        "tool_calls": sum(item["message"].get("method") == "tools/call"
                          for item in session.transcript if item["direction"] == "input"),
        "transcript": str(transcript),
    }
    named_tools = {tool["name"]: tool for tool in tools}
    metrics["named_contracts"] = {
        name: fingerprint(named_tools[name]) if name in named_tools else None
        for name in ["inspect_go_binary", "get_evidence_bundle", "export_evidence_bundle"]
    }
    if task == "retained_session":
        return metrics, results
    return metrics, {"tools": tools}


def distribution(values: list[float]) -> dict[str, float]:
    ordered = sorted(values)
    return {"median": statistics.median(ordered), "min": min(ordered), "max": max(ordered)}


def summarize(rows: list[dict]) -> dict:
    result = {}
    for task in sorted({row["task"] for row in rows}):
        result[task] = {}
        for lane in ["typescript", "native"]:
            selected = [row for row in rows if row["task"] == task and row["lane"] == lane and row["status"] == "success"]
            if not selected:
                continue
            metrics = {key: distribution([row[key] for row in selected]) for key in [
                "wall_ms", "cpu_ms", "root_wait4_maxrss_bytes", "sampled_family_peak_rss_bytes",
            ]}
            metrics["samples"] = len(selected)
            if "phases" in selected[0]:
                metrics["discovery_ms"] = distribution([row["discovery_ms"] for row in selected])
                for phase in sorted({p["phase"] for row in selected for p in row["phases"]}):
                    metrics[phase + "_ms"] = distribution([
                        sum(p["wall_ms"] for p in row["phases"] if p["phase"] == phase)
                        for row in selected
                    ])
            result[task][lane] = metrics
    return result


def prepared_commands(prepared: Path, provenance: dict) -> dict[str, list[str]]:
    toolchains = provenance.get("toolchains", {})
    native_build = provenance["builds"].get("native", {})
    result = native_build.get("result", {})
    expected_digest = result.get("sha256")
    if expected_digest is None:
        expected_digest = native_build.get("executable", {}).get("sha256")
    native = prepared / "bin" / "rea"
    if not native.is_file() or expected_digest is None:
        raise AssertionError("prepared provenance has no completed native executable")
    if sha256(native) != expected_digest:
        raise AssertionError("prepared native executable digest changed")
    npm = Path(provenance["commands"]["typescript_build"][0])
    node = npm.with_name("node")
    expected_node_digest = toolchains.get("node_sha256")
    if not node.is_file() or expected_node_digest is None or sha256(node) != expected_node_digest:
        raise AssertionError("pinned Node executable digest changed or is unavailable")
    installation = provenance.get("typescript_installation", {})
    installed_lock = prepared / "typescript" / "node_modules" / ".package-lock.json"
    if (not installed_lock.is_file()
            or sha256(installed_lock) != installation.get("installed_package_lock_sha256")):
        raise AssertionError("installed dependency lock digest changed")
    typescript_build = provenance["builds"].get("typescript", {})
    typescript_result = typescript_build.get("result", {})
    dist_rows = typescript_result.get("manifest", [])
    if typescript_build.get("status") != "complete" or not dist_rows:
        raise AssertionError("prepared provenance has no completed TypeScript build")
    if manifest_digest(dist_rows) != typescript_result.get("manifest_sha256"):
        raise AssertionError("prepared TypeScript dist manifest digest changed")
    for row in dist_rows:
        path = prepared / "typescript" / row["path"]
        if not path.is_file() or path.stat().st_size != row["bytes"] or sha256(path) != row["sha256"]:
            raise AssertionError(f"prepared TypeScript artifact changed: {row['path']}")
    return {
        "typescript": [str(node), str(prepared / "typescript/scripts/rea.mjs")],
        "native": [str(native)],
    }


def run_pair(task: str, arguments: list[str], sample: int, lane_order: list[str],
             cli: dict[str, list[str]], prepared: Path, output: Path, fixtures: dict,
             probe: bool) -> tuple[list[dict], dict[str, object]]:
    rows = []
    values = {}
    for lane in lane_order:
        row = {"task": task, "sample": sample, "lane": lane,
               "command": [*cli[lane], *arguments], "load_average_before": os.getloadavg()}
        try:
            if not probe:
                refuse_live_builds()
            if task in ["catalog", "retained_session"]:
                metrics, value = run_mcp(
                    row["command"], prepared, task, fixtures,
                    output / f"{task}-{sample}-{lane}.json",
                    output / f"{task}-{sample}-export.json",
                )
            else:
                metrics, value = run_cli(row["command"], prepared, task, fixtures)
            row.update(metrics)
            row.update(status="success", semantic_sha256=fingerprint(value))
            values[lane] = value
        except Exception as error:
            if hasattr(error, "metrics"):
                row.update(error.metrics)
            row.update(status="failure", error=f"{type(error).__name__}: {error}")
        rows.append(row)
        print(f"{task} {sample} {lane}: {row['status']}", flush=True)
    return rows, values


def compare_pair(task: str, sample: int, values: dict[str, object], rows: list[dict], output: Path) -> dict:
    comparable = set(values) == {"typescript", "native"}
    equal = comparable and values["typescript"] == values["native"]
    if comparable and not equal:
        (output / f"{task}-{sample}-difference.json").write_text(
            json.dumps(values, indent=2) + "\n"
        )
    comparison = {"task": task, "sample": sample, "both_completed": comparable,
                  "exact_structural_equal": equal}
    if task == "retained_session" and comparable:
        comparison["complete_json_semantic_equal"] = (
            semantic_mcp_value(values["typescript"]) == semantic_mcp_value(values["native"])
        )
        comparison["comparison_encoding"] = (
            "raw MCP values plus json.loads for complete JSON in top-level content text blocks"
        )
    if task == "catalog" and len(rows) == 2:
        names = {row["lane"]: set(row.get("catalog_names", [])) for row in rows}
        comparison["common_names"] = sorted(names["typescript"] & names["native"])
        comparison["typescript_only_names"] = sorted(names["typescript"] - names["native"])
        comparison["native_only_names"] = sorted(names["native"] - names["typescript"])
    if task == "retained_session" and len(rows) == 2:
        comparison["named_contracts"] = {
            row["lane"]: row.get("named_contracts", {}) for row in rows
        }
    return comparison


def semantic_mcp_value(value: object) -> object:
    """Decode valid JSON text blocks without changing any other protocol field."""
    if isinstance(value, list):
        return [semantic_mcp_value(item) for item in value]
    if not isinstance(value, dict):
        return value
    decoded = dict(value)
    content = decoded.get("content")
    if isinstance(content, list):
        blocks = []
        for block in content:
            if not isinstance(block, dict) or block.get("type") != "text" or not isinstance(block.get("text"), str):
                blocks.append(block)
                continue
            try:
                text_value = json.loads(block["text"])
            except json.JSONDecodeError:
                blocks.append(block)
                continue
            decoded_block = dict(block)
            decoded_block["text"] = text_value
            blocks.append(decoded_block)
        decoded["content"] = blocks
    return decoded


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--prepared", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--gofmt", type=Path, required=True)
    parser.add_argument("--samples", type=int, default=7)
    parser.add_argument("--probe", action="store_true", help="untimed qualification; permits concurrent builds")
    args = parser.parse_args()
    if args.samples < 1:
        parser.error("--samples must be at least 1")
    prepared = args.prepared.resolve()
    args.output = args.output.resolve()
    provenance = json.loads((prepared / "provenance.json").read_text())
    cli = prepared_commands(prepared, provenance)
    if args.output.exists():
        raise FileExistsError(args.output)
    args.output.mkdir(parents=True)
    fixtures = load_fixtures(prepared, args.gofmt)
    tasks = define_tasks(fixtures)
    document = {"schema_version": 1, "qualification_only": args.probe,
                "started_at_utc": utc_timestamp(), "harness_sha256": harness_digests(),
                "provenance_sha256": sha256(prepared / "provenance.json"),
                "fixtures": fixtures["manifest"], "rows": [], "comparisons": []}
    receipt = args.output / "results.json"
    for task, arguments in tasks.items():
        for index in range(args.samples):
            sample = index + 1
            lane_order = ["typescript", "native"] if index % 2 == 0 else ["native", "typescript"]
            rows, values = run_pair(task, arguments, sample, lane_order, cli, prepared,
                                    args.output, fixtures, args.probe)
            document["rows"].extend(rows)
            document["comparisons"].append(compare_pair(task, sample, values, rows, args.output))
            append_receipt(document, receipt)
    document["summary"] = summarize(document["rows"])
    document["finished_at_utc"] = utc_timestamp()
    append_receipt(document, receipt)


if __name__ == "__main__":
    main()
