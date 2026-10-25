#!/usr/bin/env python3
"""Bounded direct-worker comparison for frozen REA TypeScript and Rust workers."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import selectors
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from typing import Any

try:
    import psutil
except ImportError as exc:
    raise SystemExit("psutil is required for process-family RSS/CPU measurements") from exc

ROOT = pathlib.Path("/tmp/rea-direct-worker-comparison-20261026")
TS_ENTRY = pathlib.Path(
    "/Users/tihan-nico/Developer/rea-rust-ghidra-prism/.cache/runtime-benchmark-20261024-v2/typescript/dist/composition/javascriptAnalysisWorkerProcess.js"
)
DEFAULT_NODE = os.environ.get("REA_NODE", "/usr/local/bin/node")
TIMEOUT_SECONDS = 30.0
CLEANUP_GRACE_SECONDS = 2.0
OUTPUT_CAP = 128 * 1024 * 1024
FAMILY_RSS_CAP = 4 * 1024 * 1024 * 1024
MAX_RETAINED_LINE = 4096


def digest_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def process_stats(proc: subprocess.Popen[bytes]) -> tuple[int, int]:
    """Return process-family RSS and CPU microseconds without retaining output."""
    try:
        root = psutil.Process(proc.pid)
    except psutil.Error:
        return 0, 0
    family = [root]
    try:
        family.extend(root.children(recursive=True))
    except psutil.Error:
        pass
    rss = 0
    cpu_us = 0
    for member in family:
        try:
            memory = member.memory_info()
            times = member.cpu_times()
            rss += memory.rss
            cpu_us += int((times.user + times.system) * 1_000_000)
        except psutil.Error:
            continue
    return rss, cpu_us


def stop_owned_process(proc: subprocess.Popen[bytes]) -> str | None:
    if proc.poll() is not None:
        return None
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        return None
    deadline = time.monotonic() + CLEANUP_GRACE_SECONDS
    while proc.poll() is None and time.monotonic() < deadline:
        time.sleep(0.02)
    if proc.poll() is None:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        return "sigkill_after_grace"
    return "sigterm"


def bounded_text(value: bytes) -> str:
    if len(value) <= MAX_RETAINED_LINE:
        return value.decode("utf-8", "replace")
    return value[:MAX_RETAINED_LINE].decode("utf-8", "replace") + "…"


def run_one(kind: str, request_path: pathlib.Path, rust_exe: pathlib.Path | None) -> dict[str, Any]:
    request = json.loads(request_path.read_text())
    source = request["source"].encode()
    source_sha256 = hashlib.sha256(source).hexdigest()
    source_name = request.get("file", {}).get("path", request.get("path", "source.js"))
    run_id = str(uuid.uuid4())
    run_dir = ROOT / f"{kind}-{pathlib.Path(source_name).name}-{run_id}"
    run_dir.mkdir(parents=True, exist_ok=True)
    source_path = run_dir / f"{run_id}.source"
    records_path = run_dir / f"{run_id}.records"
    source_path.write_bytes(source)

    if kind == "typescript":
        node = pathlib.Path(DEFAULT_NODE)
        command = [
            str(node),
            "--max-old-space-size=1024",
            "--max-semi-space-size=8",
            "--v8-pool-size=1",
            "--expose-gc",
            "--stack_size=2048",
            str(TS_ENTRY),
        ]
    else:
        if rust_exe is None:
            raise ValueError("Rust executable is required")
        command = [
            str(rust_exe),
            "--rea-javascript-worker",
            "--rea-javascript-worker-max-heap-mb=1024",
        ]

    metadata = request["file"]
    ts_request = {
        "id": run_id,
        "node_budget": 20_000,
        "unknown_budget": 20_000,
        "text_sha256": source_sha256,
        "file": metadata,
    }
    wire = json.dumps(request, separators=(",", ":")).encode() + b"\n"
    if kind == "typescript":
        wire = json.dumps(ts_request, separators=(",", ":")).encode() + b"\n"

    started = time.monotonic()
    proc = subprocess.Popen(
        command,
        cwd=run_dir if kind == "typescript" else None,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        env={k: v for k, v in os.environ.items() if k != "NODE_OPTIONS"},
    )
    selector = selectors.DefaultSelector()
    assert proc.stdout is not None and proc.stderr is not None and proc.stdin is not None
    selector.register(proc.stdout, selectors.EVENT_READ, "stdout")
    selector.register(proc.stderr, selectors.EVENT_READ, "stderr")
    stdout_bytes = 0
    stderr_bytes = 0
    frame_count = 0
    frame_kinds: list[str] = []
    phase: str | None = None
    descriptor: dict[str, Any] | None = None
    classification = "unknown"
    error_message: str | None = None
    stderr_tail = b""
    sent_request = False
    sent_admission = False
    stdout_buffer = b""
    finished = False
    rust_final = False
    peak_rss = 0
    peak_cpu_us = 0

    def send(data: bytes) -> None:
        nonlocal sent_request, sent_admission
        proc.stdin.write(data)
        proc.stdin.flush()

    try:
        if kind == "rust":
            send(wire)
            proc.stdin.close()
            sent_request = True
        while True:
            elapsed = time.monotonic() - started
            rss, cpu_us = process_stats(proc)
            peak_rss = max(peak_rss, rss)
            peak_cpu_us = max(peak_cpu_us, cpu_us)
            if rss > FAMILY_RSS_CAP:
                classification = "family_rss_cap_exceeded"
                error_message = f"process-family RSS exceeded {FAMILY_RSS_CAP} bytes"
                break
            if elapsed >= TIMEOUT_SECONDS:
                classification = "native_timeout"
                error_message = "30-second direct-worker deadline exceeded"
                break
            if records_path.exists() and records_path.stat().st_size > OUTPUT_CAP:
                classification = "output_cap_exceeded_non_equivalent"
                error_message = "TypeScript records file exceeded 128 MiB diagnostic cap"
                break
            if proc.poll() is not None and not selector.get_map():
                break
            events = selector.select(min(0.05, TIMEOUT_SECONDS - elapsed))
            for key, _ in events:
                chunk = os.read(key.fileobj.fileno(), 64 * 1024)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if key.data == "stderr":
                    stderr_bytes += len(chunk)
                    stderr_tail = (stderr_tail + chunk)[-MAX_RETAINED_LINE:]
                    continue
                stdout_bytes += len(chunk)
                if stdout_bytes > OUTPUT_CAP:
                    classification = "output_cap_exceeded_non_equivalent"
                    error_message = "worker stdout exceeded 128 MiB diagnostic cap"
                    break
                stdout_buffer += chunk
                while b"\n" in stdout_buffer:
                    raw, stdout_buffer = stdout_buffer.split(b"\n", 1)
                    if not raw:
                        continue
                    frame_count += 1
                    try:
                        frame = json.loads(raw)
                    except json.JSONDecodeError:
                        frame_kinds.append("invalid_json")
                        continue
                    kind_name = frame.get("kind", "rust_frame")
                    frame_kinds.append(str(kind_name))
                    if kind == "typescript":
                        if kind_name == "ready" and not sent_request:
                            send(wire)
                            sent_request = True
                        elif kind_name == "static" and not sent_admission:
                            send(json.dumps({"id": run_id, "semantic_result_budget_bytes": 128 * 1024 * 1024}, separators=(",", ":")).encode() + b"\n")
                            sent_admission = True
                        elif kind_name == "phase":
                            phase = frame.get("phase")
                        elif kind_name == "complete":
                            descriptor = frame.get("descriptor")
                            classification = "complete"
                            finished = True
                        elif kind_name == "failure":
                            classification = f"typescript_failure:{frame.get('reason', 'unknown')}"
                            error_message = frame.get("message")
                            finished = True
                    elif kind == "rust":
                        if "static_analysis" in frame and "semantic_projection" not in frame:
                            phase = "static-checkpoint"
                        elif "static_analysis" in frame:
                            if "semantic_projection" in frame or "semantic_failure" in frame:
                                classification = "complete"
                                rust_final = True
                                finished = True
            if classification in {"native_timeout", "family_rss_cap_exceeded", "output_cap_exceeded_non_equivalent"}:
                break
            if finished:
                break
            if proc.poll() is not None and not selector.get_map():
                break
    finally:
        cleanup = stop_owned_process(proc)
        try:
            proc.wait(timeout=CLEANUP_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            cleanup = cleanup or "wait_timeout"
        selector.close()
        final_rss, final_cpu_us = process_stats(proc)
        if classification == "unknown":
            if proc.returncode == 0:
                classification = "complete" if descriptor is not None or rust_final else "protocol_incomplete"
            elif proc.returncode == 122:
                classification = "native_heap_exhaustion"
            else:
                classification = "process_exit_failure"
        result = {
            "kind": kind,
            "source": source_name,
            "source_bytes": len(source),
            "source_sha256": source_sha256,
            "request_sha256": digest_file(request_path),
            "executable": command[0],
            "executable_sha256": digest_file(pathlib.Path(command[0])) if pathlib.Path(command[0]).is_file() else None,
            "elapsed_ms": round((time.monotonic() - started) * 1000, 3),
            "cpu_us_final": final_cpu_us,
            "rss_bytes_final": final_rss,
            "cpu_us_peak_sample": peak_cpu_us,
            "rss_bytes_peak_sample": peak_rss,
            "measurement_note": "CPU and RSS are sampled lower bounds; final post-exit values are not measurements of peak usage.",
            "stdout_bytes": stdout_bytes,
            "stderr_bytes": stderr_bytes,
            "frame_count": frame_count,
            "frame_kinds": frame_kinds[:32],
            "phase": phase,
            "descriptor": descriptor,
            "classification": classification,
            "error": error_message,
            "stderr_tail": bounded_text(stderr_tail),
            "cleanup": cleanup,
        }
        static_path = run_dir / f"{run_id}.static.json"
        for path in (source_path, static_path, records_path):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        try:
            run_dir.rmdir()
        except OSError:
            pass
        return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rust", type=pathlib.Path, required=True)
    parser.add_argument("--request", type=pathlib.Path, action="append", default=[])
    parser.add_argument("--smoke-ts", action="store_true")
    args = parser.parse_args()
    ROOT.mkdir(parents=True, exist_ok=True)
    results = []
    if args.smoke_ts:
        synthetic = ROOT / "smoke-request.json"
        source = "const answer = 42;\n"
        synthetic.write_text(json.dumps({"source": source, "path": "smoke.js", "file": {"path": "smoke.js", "container_sha256": "0" * 64, "sha256": hashlib.sha256(source.encode()).hexdigest(), "bytes": len(source), "inventory_artifact_id": "art_smoke", "kind": "javascript", "unpacked": True}, "node_budget": 20_000, "unknown_budget": 20_000, "max_heap_mb": 1024}))
        results.append(run_one("typescript", synthetic, args.rust))
        synthetic.unlink(missing_ok=True)
    for request in args.request:
        results.append(run_one("typescript", request, args.rust))
        results.append(run_one("rust", request, args.rust))
    print(json.dumps({"results": results}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
