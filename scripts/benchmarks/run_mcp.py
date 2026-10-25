#!/usr/bin/env python3
"""Run reproducible, read-only REA MCP benchmark plans.

The runner starts one owned REA process for each workflow sample.  It records
the protocol transcript, per-call timings, process-family resource samples,
and failed calls instead of hiding them behind a later successful retry.
"""

from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import queue
import signal
import subprocess
import sys
import threading
import time
from typing import Any

import psutil


DEFAULT_CALL_TIMEOUT = 120.0
DEFAULT_SAMPLE_INTERVAL = 0.005
DEFAULT_MAX_FAMILY_RSS = 4 * 1024**3
PROCESS_CLEANUP_TIMEOUT = 15.0


def digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def normalize_wait4_maxrss(value: int) -> int:
    """Return ru_maxrss in bytes; macOS reports bytes, Linux reports KiB."""
    return value if sys.platform == "darwin" else value * 1024


def resource_counters(usage: Any) -> dict[str, int]:
    names = (
        "ru_minflt",
        "ru_majflt",
        "ru_inblock",
        "ru_oublock",
        "ru_nvcsw",
        "ru_nivcsw",
    )
    return {f"wait4_{name}": int(getattr(usage, name, 0)) for name in names}


def file_sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def resolve(value: Any, references: dict[str, Any]) -> Any:
    """Substitute plan references without changing ordinary strings."""
    if isinstance(value, str) and value.startswith("$") and value[1:] in references:
        return references[value[1:]]
    if isinstance(value, list):
        return [resolve(item, references) for item in value]
    if isinstance(value, dict):
        return {key: resolve(item, references) for key, item in value.items()}
    return value


def unresolved_reference(value: Any) -> str | None:
    if isinstance(value, str) and value.startswith("$"):
        return value
    if isinstance(value, list):
        for item in value:
            found = unresolved_reference(item)
            if found:
                return found
    if isinstance(value, dict):
        for item in value.values():
            found = unresolved_reference(item)
            if found:
                return found
    return None


def find_procedure(result: Any) -> tuple[str | None, str | None]:
    """Extract one address/name pair from a list_procedures result."""
    candidates: list[dict[str, Any]] = []

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            if isinstance(value.get("address"), (str, int)):
                candidates.append(value)
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(result)
    if not candidates:
        return None, None
    row = candidates[0]
    address = row["address"]
    name = row.get("name") or row.get("procedure") or row.get("symbol")
    return name if isinstance(name, str) else None, address if isinstance(address, str) else hex(address)


def response_failed(response: dict[str, Any]) -> bool:
    result = response.get("result")
    return bool(response.get("error") or (isinstance(result, dict) and result.get("isError")))


def response_error(response: dict[str, Any]) -> Any:
    if response.get("error") is not None:
        return response["error"]
    result = response.get("result")
    if isinstance(result, dict) and result.get("isError"):
        return result
    return None


def value_at_path(value: Any, path: str) -> Any:
    for part in path.split("."):
        if isinstance(value, dict):
            value = value[part]
        elif isinstance(value, list) and part.isdigit():
            value = value[int(part)]
        else:
            raise KeyError(path)
    return value


class FamilySampler:
    """Sample process-family RSS and CPU; both are lower-bound observations."""

    def __init__(self, pid: int, interval: float, rss_limit: int) -> None:
        self.root = psutil.Process(pid)
        self.interval = interval
        self.rss_limit = rss_limit
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        self.peak_rss = 0
        self.max_processes = 0
        self.max_gap = 0.0
        self.samples = 0
        self.sampled_user_cpu_ms = 0.0
        self.sampled_system_cpu_ms = 0.0
        self.interval_user_cpu_ms = 0.0
        self.interval_system_cpu_ms = 0.0
        self.interval_peak_rss = 0
        self.interval_max_processes = 0
        self.interval_max_gap = 0.0
        self.previous_cpu: dict[tuple[int, float], tuple[float, float]] = {}
        self.observed_processes: dict[tuple[int, float], psutil.Process] = {}
        self.limit_exceeded = threading.Event()
        self.thread = threading.Thread(target=self._collect, name="rea-benchmark-sampler", daemon=True)
        self.thread.start()

    def _snapshot(self) -> tuple[dict[tuple[int, float], tuple[float, float]], int, int]:
        try:
            processes = [self.root, *self.root.children(recursive=True)]
        except psutil.Error:
            processes = []
        cpu: dict[tuple[int, float], tuple[float, float]] = {}
        rss = 0
        observed = 0
        for process in processes:
            try:
                identity = (process.pid, process.create_time())
                times = process.cpu_times()
                cpu[identity] = (times.user, times.system)
                rss += process.memory_info().rss
                observed += 1
            except (psutil.Error, OSError):
                continue
        return cpu, rss, observed

    def _collect(self) -> None:
        previous_time = time.perf_counter()
        while not self.stop_event.is_set():
            now = time.perf_counter()
            gap = now - previous_time
            previous_time = now
            cpu, rss, observed = self._snapshot()
            with self.lock:
                for identity, (user, system) in cpu.items():
                    previous_user, previous_system = self.previous_cpu.get(identity, (0.0, 0.0))
                    user_delta = max(0.0, user - previous_user) * 1000
                    system_delta = max(0.0, system - previous_system) * 1000
                    self.interval_user_cpu_ms += user_delta
                    self.interval_system_cpu_ms += system_delta
                    self.sampled_user_cpu_ms += user_delta
                    self.sampled_system_cpu_ms += system_delta
                self.previous_cpu.update(cpu)
                for identity in cpu:
                    pid, _ = identity
                    try:
                        self.observed_processes[identity] = psutil.Process(pid)
                    except psutil.Error:
                        continue
                self.peak_rss = max(self.peak_rss, rss)
                self.interval_peak_rss = max(self.interval_peak_rss, rss)
                self.max_processes = max(self.max_processes, observed)
                self.interval_max_processes = max(self.interval_max_processes, observed)
                self.max_gap = max(self.max_gap, gap)
                self.interval_max_gap = max(self.interval_max_gap, gap)
                self.samples += 1
                if rss > self.rss_limit:
                    self.limit_exceeded.set()
            self.stop_event.wait(self.interval)

    def mark(self) -> dict[str, float | int]:
        with self.lock:
            result = {
                "sampled_family_user_cpu_ms": self.interval_user_cpu_ms,
                "sampled_family_system_cpu_ms": self.interval_system_cpu_ms,
                "sampled_family_cpu_ms": self.interval_user_cpu_ms + self.interval_system_cpu_ms,
                "sampled_family_peak_rss_bytes": self.interval_peak_rss,
                "sampled_family_max_processes": self.interval_max_processes,
                "sampled_max_gap_ms": self.interval_max_gap * 1000,
            }
            self.interval_user_cpu_ms = 0.0
            self.interval_system_cpu_ms = 0.0
            self.interval_peak_rss = 0
            self.interval_max_processes = 0
            self.interval_max_gap = 0.0
            return result

    def finish(self) -> dict[str, float | int]:
        self.stop_event.set()
        self.thread.join(timeout=max(1.0, self.interval * 4))
        with self.lock:
            return {
                "sampled_family_peak_rss_bytes": self.peak_rss,
                "sampled_family_user_cpu_ms": self.sampled_user_cpu_ms,
                "sampled_family_system_cpu_ms": self.sampled_system_cpu_ms,
                "sampled_family_cpu_ms": self.sampled_user_cpu_ms + self.sampled_system_cpu_ms,
                "sampled_family_max_processes": self.max_processes,
                "sample_count": self.samples,
                "sampled_max_gap_ms": self.max_gap * 1000,
            }


class OwnedProcess:
    def __init__(self, command: list[str], work_dir: Path, timeout: float, rss_limit: int,
                 worker: Path | None) -> None:
        environment = os.environ.copy()
        environment["HOME"] = str(work_dir / "home")
        environment["XDG_CONFIG_HOME"] = str(work_dir / "xdg-config")
        environment["XDG_CACHE_HOME"] = str(work_dir / "xdg-cache")
        environment["XDG_DATA_HOME"] = str(work_dir / "xdg-data")
        environment["REA_CONFIG"] = str(work_dir / "rea-config.json")
        environment["REA_GHIDRA_RUST_CACHE_DIR"] = str(work_dir / "ghidra-cache")
        if worker is not None:
            environment["REA_GHIDRA_RUST_WORKER"] = str(worker)
        environment["LC_ALL"] = "C"
        for directory in ("home", "xdg-config", "xdg-cache", "xdg-data", "ghidra-cache"):
            (work_dir / directory).mkdir(parents=True, exist_ok=True)
        self.started = time.perf_counter()
        self.process = subprocess.Popen(
            command,
            cwd=work_dir,
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=(os.name != "nt"),
        )
        self.timeout = timeout
        self.sampler = FamilySampler(self.process.pid, DEFAULT_SAMPLE_INTERVAL, rss_limit)
        self.abort_reason: str | None = None
        self.termination_error: str | None = None
        self.messages: queue.Queue[tuple[bytes, int]] = queue.Queue(maxsize=4096)
        self.stdout_overflow = threading.Event()
        self.stdout_done = threading.Event()
        self.stderr = bytearray()
        self.readers = [
            threading.Thread(target=self._read_stdout, daemon=True),
            threading.Thread(target=self._read_stderr, daemon=True),
        ]
        for reader in self.readers:
            reader.start()

    def _read_stdout(self) -> None:
        assert self.process.stdout is not None
        try:
            for line in self.process.stdout:
                try:
                    self.messages.put_nowait((line, len(line)))
                except queue.Full:
                    self.stdout_overflow.set()
                    self.terminate("stdout-queue-limit")
                    break
        finally:
            self.stdout_done.set()

    def _read_stderr(self) -> None:
        assert self.process.stderr is not None
        for chunk in iter(lambda: self.process.stderr.read(4096), b""):
            self.stderr.extend(chunk)
            del self.stderr[:-16_384]

    def terminate(self, reason: str) -> str:
        try:
            if os.name == "nt":
                self.process.kill()
            else:
                os.killpg(self.process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except PermissionError as exc:
            self._record_cleanup_error(f"{type(exc).__name__}: {exc}")
        self._terminate_observed_descendants()
        return reason

    def _terminate_observed_descendants(self) -> None:
        """Kill only descendants whose PID and creation time were observed."""
        cleanup_errors: list[str] = []
        with self.sampler.lock:
            observed = list(self.sampler.observed_processes.items())
        for identity, process in observed:
            if identity[0] == self.process.pid:
                continue
            try:
                if process.create_time() != identity[1]:
                    continue
                process.kill()
            except psutil.NoSuchProcess:
                continue
            except (psutil.AccessDenied, OSError) as exc:
                cleanup_errors.append(f"{identity[0]}: {type(exc).__name__}: {exc}")
        if cleanup_errors:
            for error in cleanup_errors:
                self._record_cleanup_error(error)

    def _record_cleanup_error(self, error: str) -> None:
        if self.termination_error:
            self.termination_error += "; " + error
        else:
            self.termination_error = error

    def _remaining_observed_descendants(self) -> list[int]:
        remaining: list[int] = []
        with self.sampler.lock:
            observed = list(self.sampler.observed_processes.items())
        for identity, process in observed:
            if identity[0] == self.process.pid:
                continue
            try:
                if process.create_time() == identity[1] and process.is_running():
                    remaining.append(identity[0])
            except psutil.NoSuchProcess:
                continue
            except (psutil.AccessDenied, OSError) as exc:
                self._record_cleanup_error(f"{identity[0]}: {type(exc).__name__}: {exc}")
        return sorted(set(remaining))

    def _wait_for_observed_descendants(self, timeout: float = 2.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not self._remaining_observed_descendants():
                return
            time.sleep(0.05)

    def emergency_cleanup(self) -> None:
        try:
            self.terminate("cleanup-retry")
        except (OSError, psutil.Error) as exc:
            self._record_cleanup_error(f"terminate: {type(exc).__name__}: {exc}")
        if os.name != "nt":
            try:
                os.wait4(self.process.pid, 0)
            except ChildProcessError:
                pass
            except OSError as exc:
                self._record_cleanup_error(f"reap: {type(exc).__name__}: {exc}")
        try:
            self.sampler.finish()
        except (OSError, psutil.Error) as exc:
            self._record_cleanup_error(f"sampler: {type(exc).__name__}: {exc}")
        for reader in self.readers:
            reader.join(timeout=PROCESS_CLEANUP_TIMEOUT)

    def _close_stdin(self) -> None:
        if self.process.stdin is not None:
            try:
                self.process.stdin.close()
            except BrokenPipeError:
                pass

    def _wait_for_root(self, reason: str) -> tuple[str, Any]:
        deadline = time.monotonic() + PROCESS_CLEANUP_TIMEOUT
        termination = reason
        waited = None
        while waited is None and (os.name == "nt" and self.process.poll() is None or os.name != "nt"):
            if os.name != "nt":
                waited_pid, waited_status, waited_usage = os.wait4(self.process.pid, os.WNOHANG)
                if waited_pid:
                    waited = (waited_status, waited_usage)
                    break
            if time.monotonic() >= deadline:
                termination = self.terminate("process-timeout")
                if os.name != "nt":
                    waited_pid, waited_status, waited_usage = os.wait4(self.process.pid, 0)
                    waited = (waited_status, waited_usage)
                break
            if self.sampler.peak_rss > self.sampler.rss_limit:
                termination = self.terminate("family-rss-limit")
                break
            time.sleep(0.001)
        return termination, waited

    def _reap_root(self, waited: Any) -> tuple[int, dict[str, Any]]:
        """Reap the owned root and normalize its OS resource accounting."""
        if os.name == "nt":
            return self.process.wait(timeout=PROCESS_CLEANUP_TIMEOUT), {}

        if waited is None:
            waited_pid, status, usage = os.wait4(self.process.pid, 0)
            if waited_pid != self.process.pid:
                raise RuntimeError("wait4 returned an unexpected child")
        else:
            status, usage = waited

        returncode = os.waitstatus_to_exitcode(status)
        self.process.returncode = returncode
        metrics = {
            "root_user_cpu_ms": usage.ru_utime * 1000,
            "root_system_cpu_ms": usage.ru_stime * 1000,
            "wait4_user_cpu_ms": usage.ru_utime * 1000,
            "wait4_system_cpu_ms": usage.ru_stime * 1000,
            "wait4_maxrss": normalize_wait4_maxrss(usage.ru_maxrss),
            "wait4_maxrss_unit": "bytes",
            "wait4_cpu_scope": "OS wait4 resource usage; may include waited descendants",
            **resource_counters(usage),
        }
        return returncode, metrics

    def finish(self, reason: str = "stdin-eof") -> dict[str, Any]:
        self._close_stdin()
        termination, waited = self._wait_for_root(reason)
        returncode, root_metrics = self._reap_root(waited)
        self._terminate_observed_descendants()
        self._wait_for_observed_descendants()
        for reader in self.readers:
            reader.join(timeout=PROCESS_CLEANUP_TIMEOUT)
        elapsed = (time.perf_counter() - self.started) * 1000
        usage = self.sampler.finish()
        return {
            "wall_ms": elapsed,
            "exit_code": returncode,
            "termination": termination,
            "termination_error": self.termination_error,
            "reader_threads_alive": [reader.name for reader in self.readers if reader.is_alive()],
            "remaining_observed_descendants": self._remaining_observed_descendants(),
            **root_metrics,
            "sampled_cpu_accounting": "recursive psutil deltas; lower bound and may miss exited-child tail",
            "stderr": self.stderr.decode(errors="replace")[-16_384:],
            **usage,
        }


class McpClient:
    def __init__(self, child: OwnedProcess, output_dir: Path, timeout: float) -> None:
        self.child = child
        self.output_dir = output_dir
        self.timeout = timeout
        self.request_id = 0
        self.references: dict[str, Any] = {}
        self.calls: list[dict[str, Any]] = []

    def _write(self, message: dict[str, Any]) -> None:
        assert self.child.process.stdin is not None
        self.child.process.stdin.write(json.dumps(message, separators=(",", ":")).encode() + b"\n")
        self.child.process.stdin.flush()

    def request(self, method: str, params: dict[str, Any], label: str,
                retain_response: bool = True) -> dict[str, Any]:
        self.request_id += 1
        request_id = self.request_id
        request = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
        started = time.perf_counter()
        self.child.sampler.mark()
        response: dict[str, Any] | None = None
        error: str | None = None
        output_bytes = 0
        raw_lines: list[str] = []
        try:
            self._write(request)
            deadline = time.monotonic() + self.timeout
            while time.monotonic() < deadline:
                if self.child.sampler.limit_exceeded.is_set():
                    raise MemoryError("process-family RSS limit exceeded")
                if self.child.stdout_overflow.is_set():
                    raise MemoryError("MCP stdout queue limit exceeded")
                try:
                    raw, size = self.child.messages.get(timeout=min(0.2, max(0.01, deadline - time.monotonic())))
                except queue.Empty:
                    if self.child.sampler.limit_exceeded.is_set():
                        raise MemoryError("process-family RSS limit exceeded")
                    if self.child.stdout_done.is_set():
                        raise RuntimeError("MCP process exited before response")
                    continue
                output_bytes += size
                raw_lines.append(raw.decode(errors="replace"))
                candidate = json.loads(raw)
                if candidate.get("id") == request_id:
                    response = candidate
                    break
            if response is None:
                raise TimeoutError(f"MCP call timed out after {self.timeout}s")
        except Exception as exc:  # retain the failure row before stopping unsafe work
            error = f"{type(exc).__name__}: {exc}"
            if isinstance(exc, (TimeoutError, MemoryError)):
                self.child.abort_reason = error
                reason = "call-timeout" if isinstance(exc, TimeoutError) else (
                    "stdout-queue-limit"
                    if self.child.stdout_overflow.is_set()
                    else "family-rss-limit"
                )
                self.child.terminate(reason)
        after = self.child.sampler.mark()
        row: dict[str, Any] = {
            "label": label,
            "method": method,
            "request": request,
            "wall_ms": (time.perf_counter() - started) * 1000,
            "output_bytes": output_bytes,
            "status": "success" if response is not None and not response_failed(response) else "failure",
            "error": error or (response_error(response) if response else None),
            "sampled_family_cpu_ms": after["sampled_family_cpu_ms"],
            "sampled_family_user_cpu_ms": after["sampled_family_user_cpu_ms"],
            "sampled_family_system_cpu_ms": after["sampled_family_system_cpu_ms"],
            "sampled_family_peak_rss_bytes": after["sampled_family_peak_rss_bytes"],
            "sampled_family_max_processes": after["sampled_family_max_processes"],
            "sampled_max_gap_ms": after["sampled_max_gap_ms"],
        }
        if response is not None:
            row["response_sha256"] = digest(response)
            row["response"] = response
            result = response.get("result")
            if method == "tools/call" and isinstance(result, dict):
                name = request["params"].get("name")
                if name == "list_procedures":
                    procedure, address = find_procedure(result)
                    if address is not None:
                        self.references["address"] = address
                        if procedure is not None:
                            self.references["procedure"] = procedure
        if not retain_response:
            row.pop("response", None)
        elif response is None:
            row["raw_json_lines"] = raw_lines
        self.calls.append(row)
        self.output_dir.joinpath(f"call-{len(self.calls):04d}.json").write_text(json.dumps(row, indent=2) + "\n")
        return response or {"error": row["error"]}

    def tool(self, name: str, arguments: dict[str, Any], label: str) -> dict[str, Any]:
        resolved = resolve(arguments, self.references)
        missing = unresolved_reference(resolved)
        if missing:
            raise ValueError(f"unresolved benchmark reference {missing}; prerequisite call did not produce it")
        return self.request("tools/call", {"name": name, "arguments": resolved}, label)


def discover_catalog(client: McpClient, work_dir: Path) -> tuple[dict[str, Any] | None, str | None]:
    catalog_path = work_dir / "catalog.json"
    catalog = client.request("tools/list", {}, "tools-list", retain_response=not catalog_path.exists())
    if not catalog_path.exists() and not response_failed(catalog):
        catalog_path.write_text(json.dumps(catalog, indent=2) + "\n")
    elif catalog_path.exists():
        if response_failed(catalog):
            return json.loads(catalog_path.read_text()), "tools/list failed; cached catalog was not validated"
        catalog = json.loads(catalog_path.read_text())
    elif response_failed(catalog):
        return catalog, "tools/list failed; catalog was not written"
    return catalog, None


def execute_workflow_cases(client: McpClient, child: OwnedProcess,
                           workflow: dict[str, Any]) -> str | None:
    failure: str | None = None
    for case in workflow.get("cases", []):
        repeat = int(case.get("repeat", 1))
        for iteration in range(repeat):
            case_label = case.get("label", case["name"])
            label = f"{case_label}#{iteration + 1}"
            response = client.tool(case["name"], case.get("arguments", {}), label)
            if response_failed(response):
                failure = failure or f"{label}: tool failure"
            for alias, path in case.get("capture", {}).items():
                try:
                    client.references[alias] = value_at_path(response, path)
                except (KeyError, IndexError, TypeError) as exc:
                    failure = failure or f"{label}: capture {alias} failed: {exc}"
            if child.abort_reason:
                return failure or child.abort_reason
    return failure


def run_workflow(plan: dict[str, Any], workflow: dict[str, Any], round_number: int,
                 executable: Path, worker: Path | None, work_dir: Path,
                 timeout: float, rss_limit: int) -> dict[str, Any]:
    workflow_started_utc = datetime.now(timezone.utc).isoformat()
    harness_started_cpu = time.process_time()
    output_dir = work_dir / f"{workflow['name']}-round-{round_number:03d}"
    if output_dir.exists():
        raise FileExistsError(f"workflow output already exists: {output_dir}")
    output_dir.mkdir(parents=True)
    command = [str(executable), "mcp"]
    child = OwnedProcess(command, output_dir, timeout, rss_limit, worker)
    client = McpClient(child, output_dir, timeout)
    client.references["export_path"] = str(output_dir / "evidence-export.json")
    target = workflow.get("target", plan.get("target"))
    if target:
        target_path = str(Path(target).expanduser().resolve())
        client.references["target"] = target_path
        client.references["bundle"] = target_path
        target_path_object = Path(target_path)
        plist_path = target_path_object / "Contents/Info.plist" if target_path_object.is_dir() else target_path_object
        client.references["plist"] = str(plist_path)
    failure: str | None = None
    catalog: dict[str, Any] | None = None
    process_metrics: dict[str, Any] = {}
    try:
        initialized = client.request("initialize", {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "rea-local-benchmark", "version": "1"},
        }, "initialize")
        if response_failed(initialized):
            failure = "initialize failed"
            raise RuntimeError("initialize failed; MCP session is not usable")
        client._write({"jsonrpc": "2.0", "method": "notifications/initialized"})
        catalog, catalog_failure = discover_catalog(client, work_dir)
        execution_failure = execute_workflow_cases(client, child, workflow)
        failure = catalog_failure or execution_failure
    except Exception as exc:
        failure = f"{type(exc).__name__}: {exc}"
    finally:
        try:
            process_metrics = child.finish(
                child.abort_reason or ("workflow-failure" if failure else "stdin-eof")
            )
        except Exception as exc:
            child.emergency_cleanup()
            process_metrics = {
                "termination": "cleanup-error",
                "termination_error": "; ".join(
                    item for item in [
                        f"{type(exc).__name__}: {exc}",
                        child.termination_error,
                    ] if item
                ),
            }
            failure = failure or process_metrics["termination_error"]
    if (process_metrics.get("termination_error")
            or process_metrics.get("remaining_observed_descendants")
            or process_metrics.get("reader_threads_alive")):
        failure = failure or "process cleanup incomplete"
    receipt = {
        "schema_version": 1,
        "plan": plan,
        "workflow": workflow,
        "round": round_number,
        "started_at_utc": workflow_started_utc,
        "ended_at_utc": datetime.now(timezone.utc).isoformat(),
        "harness_cpu_ms": (time.process_time() - harness_started_cpu) * 1000,
        "command": command,
        "status": "failure" if failure or process_metrics.get("exit_code", 1) else "success",
        "error": failure,
        "calls": client.calls,
        "references": client.references,
        "catalog_sha256": digest(catalog) if isinstance(catalog, dict) else None,
        "catalog_tools": [
            tool.get("name")
            for tool in catalog.get("result", {}).get("tools", [])
            if isinstance(tool, dict) and isinstance(tool.get("name"), str)
        ] if isinstance(catalog, dict) else [],
        "process": process_metrics,
    }
    output_dir.joinpath("receipt.json").write_text(
        json.dumps(compact_receipt(receipt), indent=2) + "\n"
    )
    return receipt


def compact_receipt(receipt: dict[str, Any]) -> dict[str, Any]:
    """Keep aggregate output small; detailed responses stay in work-dir files."""
    compact = {key: value for key, value in receipt.items() if key != "calls"}
    compact["calls"] = []
    for call in receipt["calls"]:
        compact["calls"].append({
            key: value
            for key, value in call.items()
            if key not in {"response", "raw_json_lines"}
        })
    return compact


def write_aggregate(output: Path, plan: dict[str, Any], args: argparse.Namespace,
                    receipts: list[dict[str, Any]]) -> None:
    result = {
        "schema_version": 1,
        "plan_sha256": digest(plan),
        "plan_path": str(args.plan.resolve()),
        "rea_path": str(args.rea.resolve()),
        "worker_path": str(args.worker.resolve()) if args.worker else None,
        "rea_sha256": file_sha256(args.rea),
        "worker_sha256": file_sha256(args.worker) if args.worker else None,
        "python": sys.version,
        "psutil": psutil.__version__,
        "platform": sys.platform,
        "machine": os.uname().machine if hasattr(os, "uname") else None,
        "rounds": args.rounds,
        "receipts": [compact_receipt(receipt) for receipt in receipts],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--rea", type=Path, required=True)
    parser.add_argument("--worker", type=Path)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--call-timeout", type=float, default=DEFAULT_CALL_TIMEOUT)
    parser.add_argument("--max-family-rss", type=int, default=DEFAULT_MAX_FAMILY_RSS)
    parser.add_argument("--only", action="append", help="run only this workflow name; repeatable")
    args = parser.parse_args()
    plan = json.loads(args.plan.read_text())
    if args.work_dir.exists() and any(args.work_dir.iterdir()):
        raise FileExistsError(f"work directory must be empty: {args.work_dir}")
    args.work_dir.mkdir(parents=True, exist_ok=True)
    receipts = []
    workflows = plan.get("workflows", [])
    if args.only:
        selected = set(args.only)
        unknown = selected - {workflow["name"] for workflow in workflows}
        if unknown:
            parser.error(f"unknown workflow(s): {', '.join(sorted(unknown))}")
        workflows = [workflow for workflow in workflows if workflow["name"] in selected]
    for round_number in range(1, args.rounds + 1):
        round_workflows = list(reversed(workflows)) if round_number % 2 == 0 else workflows
        for workflow in round_workflows:
            receipts.append(compact_receipt(run_workflow(
                plan, workflow, round_number, args.rea, args.worker,
                args.work_dir, args.call_timeout, args.max_family_rss,
            )))
            write_aggregate(args.output, plan, args, receipts)
            print(f"completed {workflow['name']} round {round_number}", flush=True)
    with args.output.with_suffix(".csv").open("w", newline="") as stream:
        fields = ["workflow", "round", "status", "error", "wall_ms", "exit_code",
                  "sampled_family_peak_rss_bytes", "sampled_family_cpu_ms"]
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for receipt in receipts:
            process = receipt["process"]
            row = {field: process.get(field) for field in fields}
            row.update({"workflow": receipt["workflow"]["name"], "round": receipt["round"],
                        "status": receipt["status"], "error": receipt["error"]})
            writer.writerow(row)
    return 0 if all(receipt["status"] == "success" for receipt in receipts) else 1


if __name__ == "__main__":
    raise SystemExit(main())
