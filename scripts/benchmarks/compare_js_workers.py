#!/usr/bin/env python3
"""Compare two Rust JavaScript workers on immutable Electron ASAR fixtures.

The runner records bounded process and protocol metadata. It never writes ASAR
contents, semantic frames, or raw stderr to the output receipt.
"""
from __future__ import annotations

import argparse
import base64
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
import platform
from pathlib import Path
import selectors
import signal
import subprocess
import tempfile
import time
import zlib
from typing import Any

import psutil

TIMEOUT_SECONDS = 30.0
MAX_HEAP_MB = 1024
NODE_BUDGET = 20_000
UNKNOWN_BUDGET = 20_000
MAX_OUTPUT_BYTES = 64 * 1024 * 1024
MAX_FAMILY_RSS = 4 * 1024**3
MAX_FRAME_HASHES = 128
MAX_FRAME_BUFFER = MAX_OUTPUT_BYTES
MAX_DECODED_BYTES = MAX_HEAP_MB * 1024 * 1024 // 4
CLEANUP_SECONDS = 2.0
FAMILY_SAMPLE_INTERVAL_SECONDS = 0.05
DEFAULT_FIGMA = Path("/Applications/Figma.app/Contents/Resources/app.asar")
DEFAULT_POSTMAN = Path("/Applications/Postman.app/Contents/Resources/app.asar")
EXPECTED = {
    "figma-main": (3_632_793, "5ff5373b176c282f7389aa437a0d553bcd3dbf9ff5846dfac1f3641cdee40371"),
    "postman-agent-worker": (10_794_503, "dd0391ddedd4907dab0866816f1a7251ee2b57054828bcb596ed074b7fd32280"),
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class DuplicateJsonKeyError(ValueError):
    """Raised when a worker frame repeats an object key."""


def parse_worker_json(raw: bytes | bytearray) -> Any:
    """Parse worker JSON with the same duplicate-key discipline as serde."""

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise DuplicateJsonKeyError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    return json.loads(raw, object_pairs_hook=reject_duplicates)


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def benchmark_provenance() -> dict[str, Any]:
    try:
        load = list(os.getloadavg())
    except OSError:
        load = None
    return {
        "script_sha256": sha256_file(Path(__file__).resolve()),
        "host": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "logical_cpu_count": os.cpu_count(),
        },
        "load_average": load,
    }


def parse_asar_extents(prefix: bytes, archive_size: int) -> tuple[int, int]:
    if len(prefix) < 16 or int.from_bytes(prefix[0:4], "little") != 4:
        raise ValueError("ASAR size pickle is invalid")
    header_bytes = int.from_bytes(prefix[4:8], "little")
    payload_bytes = int.from_bytes(prefix[8:12], "little")
    json_bytes = int.from_bytes(prefix[12:16], "little")
    if header_bytes < 8 or payload_bytes != header_bytes - 4 or json_bytes > payload_bytes - 4:
        raise ValueError("ASAR Pickle extents are invalid")
    if header_bytes > archive_size - 8:
        raise ValueError("ASAR header exceeds archive")
    return header_bytes, json_bytes


def asar_header(path: Path) -> tuple[dict[str, Any], int]:
    archive_size = path.stat().st_size
    with path.open("rb") as stream:
        prefix = stream.read(16)
        header_bytes, json_bytes = parse_asar_extents(prefix, archive_size)
        raw = stream.read(json_bytes)
    if len(raw) != json_bytes:
        raise ValueError(f"ASAR header is truncated: {path}")
    value = json.loads(raw)
    if not isinstance(value, dict) or not isinstance(value.get("files"), dict):
        raise ValueError("ASAR header does not contain a files object")
    return value, header_bytes


def walk_entries(node: dict[str, Any], parent: str = "") -> list[tuple[str, dict[str, Any]]]:
    files = node.get("files")
    if not isinstance(files, dict):
        return []
    entries: list[tuple[str, dict[str, Any]]] = []
    for name, child in files.items():
        if not isinstance(child, dict):
            raise ValueError(f"ASAR entry metadata is invalid: {name}")
        path = f"{parent}/{name}" if parent else name
        entries.append((path, child))
        entries.extend(walk_entries(child, path))
    return entries


def select_member(header: dict[str, Any], requested: str) -> tuple[str, dict[str, Any]]:
    root = header
    node: dict[str, Any] = root
    found = True
    for part in requested.split("/"):
        files = node.get("files")
        if not isinstance(files, dict) or part not in files:
            found = False
            break
        node = files[part]
        if not isinstance(node, dict):
            raise ValueError(f"ASAR member metadata is invalid: {requested}")
    if found and not isinstance(node.get("files"), dict):
        return requested, node
    matches = [(path, entry) for path, entry in walk_entries(root) if path.endswith("/" + requested) or path == requested]
    if len(matches) != 1:
        raise ValueError(f"ASAR member suffix is not unique: {requested} ({len(matches)} matches)")
    return matches[0]


def validate_integrity(data: bytes, entry: dict[str, Any]) -> None:
    integrity = entry.get("integrity")
    if not isinstance(integrity, dict) or str(integrity.get("algorithm", "")).upper() != "SHA256":
        return
    expected = integrity.get("hash")
    if isinstance(expected, str) and expected != sha256_bytes(data):
        raise ValueError("ASAR member SHA256 integrity mismatch")
    blocks = integrity.get("blocks")
    block_size = integrity.get("blockSize")
    if isinstance(blocks, list) and isinstance(block_size, int) and block_size > 0:
        actual = [sha256_bytes(data[i : i + block_size]) for i in range(0, len(data), block_size)] or [sha256_bytes(b"")]
        if actual != blocks:
            raise ValueError("ASAR member block integrity mismatch")


def read_asar_member(path: Path, requested: str) -> tuple[str, bytes, dict[str, Any], dict[str, Any]]:
    header, header_bytes = asar_header(path)
    member, entry = select_member(header, requested)
    size, offset = entry.get("size"), entry.get("offset")
    if not isinstance(size, int) or size < 0 or not isinstance(offset, (str, int)):
        raise ValueError(f"ASAR member has no packed extent: {member}")
    start = 8 + header_bytes + int(offset)
    if start < 0 or start + size > path.stat().st_size:
        raise ValueError(f"ASAR member extent is outside archive: {member}")
    with path.open("rb") as stream:
        stream.seek(start)
        data = stream.read(size)
    if len(data) != size:
        raise ValueError(f"ASAR member is truncated: {member}")
    validate_integrity(data, entry)
    digest = sha256_bytes(data)
    return member, data, entry, {"bytes": size, "sha256": digest, "archive_sha256": sha256_file(path), "offset": start}


@dataclass(frozen=True)
class Fixture:
    name: str
    archive: Path
    requested_member: str


def load_fixtures(figma: Path, postman: Path, extras: list[Path]) -> list[Fixture]:
    fixtures = [Fixture("figma-main", figma, "main.js"), Fixture("postman-agent-worker", postman, "AgentWorker.js")]
    for config in extras:
        values = json.loads(config.read_text())
        if isinstance(values, dict):
            values = [values]
        if not isinstance(values, list):
            raise ValueError("fixture config must contain a list")
        for value in values:
            fixtures.append(
                Fixture(
                    str(value["name"]),
                    Path(value["archive"]),
                    str(value["member"]),
                )
            )
    return fixtures


class FrameAccumulator:
    def __init__(self, compare_semantic_fields: bool = False) -> None:
        self.buffer = bytearray()
        self.count = 0
        self.bytes = 0
        self.hashes: list[str] = []
        self.kinds: Counter[str] = Counter()
        self.errors: list[str] = []
        self.final_projection = False
        self.semantic_failure = False
        self.protocol_invalid = False
        self.scan_offset = 0
        self.coverage: dict[str, Any] | None = None
        self.projection_counts: dict[str, int | bool] = {}
        self.semantic_hashes: dict[str, str] = {}
        self.compare_semantic_fields = compare_semantic_fields
        self.static_checkpoint: Any = None
        self.decoded_bytes = 0
        self.decoded_sha256: str | None = None
        self.encoding: str | None = None
        self.compressed_terminal_count = 0
        self.decoded_frame_count = 0
        self.spool = tempfile.TemporaryFile()
        self.validated = False

    def feed(self, chunk: bytes) -> None:
        if self.protocol_invalid:
            return
        self.buffer.extend(chunk)
        if len(self.buffer) > MAX_FRAME_BUFFER:
            self.reject("frame-buffer-cap")
            self.buffer.clear()
            return

        while True:
            newline = self.buffer.find(b"\n", self.scan_offset)
            if newline < 0:
                self.scan_offset = len(self.buffer)
                return
            raw = bytes(self.buffer[:newline])
            del self.buffer[: newline + 1]
            self.scan_offset = 0
            self._capture(raw)

    def finish(self) -> None:
        if not self.protocol_invalid and self.buffer.strip():
            self._capture(bytes(self.buffer))
        self.buffer.clear()

    def _capture(self, raw: bytes) -> None:
        if not raw:
            return
        self.count += 1
        self.bytes += len(raw)
        self.spool.write(len(raw).to_bytes(8, "big"))
        self.spool.write(raw)
        if len(self.hashes) < MAX_FRAME_HASHES:
            self.hashes.append(sha256_bytes(raw))

    def validate(self) -> None:
        if self.validated:
            return
        self.validated = True
        self.spool.seek(0)
        while True:
            length = self.spool.read(8)
            if not length:
                break
            raw = self.spool.read(int.from_bytes(length, "big"))
            self._decode_frame(raw)

    def reject(self, reason: str) -> None:
        self.protocol_invalid = True
        if len(self.errors) < 16:
            self.errors.append(reason)

    def _decode_frame(self, raw: bytes) -> None:
        if not raw:
            return
        try:
            value = parse_worker_json(raw)
        except (DuplicateJsonKeyError, json.JSONDecodeError, UnicodeDecodeError):
            self.reject("invalid-json")
            return
        if not isinstance(value, dict):
            self.reject("frame-not-object")
            return
        if "protocol" in value and value.get("protocol") != "rea-worker-compressed-v1":
            self.reject("unsupported-protocol")
            return
        if value.get("protocol") == "rea-worker-compressed-v1":
            value = self._decode_compressed_terminal(value)
            if value is None:
                return
        if self.decoded_frame_count == 0 and set(value) != {"static_analysis"}:
            self.reject("invalid-static-checkpoint")
            return
        self.decoded_frame_count += 1
        kind = str(value.get("kind") or ("final" if "semantic_projection" in value else "message"))
        self.kinds[kind] += 1
        if value.get("static_analysis") is not None:
            self.static_checkpoint = value["static_analysis"]
        if value.get("semantic_projection") is not None:
            self.final_projection = True
            self.retain_semantic_summary(value)
        if value.get("semantic_failure") is not None:
            self.semantic_failure = True
            if len(self.errors) < 16:
                self.errors.append("semantic-failure")
        if value.get("error") is not None or kind in {"failure", "error"}:
            self.reject("worker-error")

    def _decode_compressed_terminal(self, envelope: dict[str, Any]) -> dict[str, Any] | None:
        fields = self._validate_compressed_envelope(envelope)
        if fields is None:
            return None
        payload, expected_bytes = fields

        self.compressed_terminal_count += 1
        if self.compressed_terminal_count != 1:
            self.reject("multiple-compressed-terminals")
            return None
        if expected_bytes < 0 or expected_bytes > MAX_DECODED_BYTES:
            self.reject("decoded-budget-exceeded")
            return None

        try:
            encoded = base64.b64decode(payload.encode("ascii"), validate=True)
        except (ValueError, UnicodeEncodeError):
            self.reject("invalid-base64")
            return None

        decoded = self._inflate_compressed_payload(encoded)
        if decoded is None:
            return None
        if len(decoded) != expected_bytes:
            self.reject("decoded-byte-count-mismatch")
            return None

        body = self._validate_decoded_body(decoded)
        if body is None:
            return None
        body["static_analysis"] = self.static_checkpoint
        self.encoding = "gzip+base64"
        self.decoded_bytes = len(decoded)
        self.decoded_sha256 = sha256_bytes(decoded)
        return body

    def _validate_compressed_envelope(
        self,
        envelope: dict[str, Any],
    ) -> tuple[str, int] | None:
        if set(envelope) != {"protocol", "version", "encoding", "decoded_bytes", "payload"}:
            self.reject("compressed-envelope-keys")
            return None

        if (
            envelope["protocol"] != "rea-worker-compressed-v1"
            or type(envelope["version"]) is not int
            or envelope["version"] != 1
            or envelope["encoding"] != "gzip+base64"
        ):
            self.reject("compressed-envelope-version-or-encoding")
            return None

        payload = envelope.get("payload")
        expected_bytes = envelope.get("decoded_bytes")
        if not isinstance(payload, str) or type(expected_bytes) is not int:
            self.reject("compressed-envelope-fields")
            return None
        return payload, expected_bytes

    def _inflate_compressed_payload(self, encoded: bytes) -> bytes | None:
        try:
            inflater = zlib.decompressobj(wbits=31)
            decoded = bytearray()
            for offset in range(0, len(encoded), 64 * 1024):
                decoded.extend(
                    inflater.decompress(
                        encoded[offset : offset + 64 * 1024],
                        MAX_DECODED_BYTES + 1 - len(decoded),
                    )
                )
                if len(decoded) > MAX_DECODED_BYTES:
                    self.reject("decoded-budget-exceeded")
                    return None

            if inflater.unconsumed_tail:
                self.reject("decoded-budget-exceeded")
                return None
            decoded.extend(inflater.flush())
            if len(decoded) > MAX_DECODED_BYTES:
                self.reject("decoded-budget-exceeded")
                return None
            if not inflater.eof or inflater.unused_data or inflater.unconsumed_tail:
                self.reject("gzip-integrity-or-trailing-data")
                return None
        except zlib.error:
            self.reject("gzip-integrity-error")
            return None
        return bytes(decoded)

    def _validate_decoded_body(self, decoded: bytes) -> dict[str, Any] | None:
        try:
            body = parse_worker_json(decoded)
        except (DuplicateJsonKeyError, json.JSONDecodeError, UnicodeDecodeError):
            self.reject("decoded-json-invalid")
            return None
        if not isinstance(body, dict):
            self.reject("decoded-body-not-object")
            return None
        if self.static_checkpoint is None:
            self.reject("missing-static-checkpoint")
            return None
        if set(body) - {
            "semantic_ir",
            "semantic_projection",
            "semantic_metadata",
            "semantic_failure",
        }:
            self.reject("decoded-body-keys")
            return None
        return body

    def retain_semantic_summary(self, response: dict[str, Any]) -> None:
        if self.compare_semantic_fields:
            for field in (
                "static_analysis",
                "semantic_ir",
                "semantic_projection",
                "semantic_metadata",
                "semantic_failure",
            ):
                value = response.get(field)
                canonical = json.dumps(
                    value,
                    ensure_ascii=True,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("ascii")
                self.semantic_hashes[field] = sha256_bytes(canonical)

        metadata = response.get("semantic_metadata")
        coverage = metadata.get("coverage") if isinstance(metadata, dict) else None
        if isinstance(coverage, dict):
            status = coverage.get("status")
            omitted = coverage.get("omittedCount")
            limits = coverage.get("resourceLimits")
            self.coverage = {
                "status": status if status in {"complete", "partial", "failed"} else "unknown",
                "omitted_count": omitted if type(omitted) is int else None,
                "resource_limit_count": len(limits) if isinstance(limits, list) else None,
            }

        projection = response.get("semantic_projection")
        if isinstance(projection, dict):
            for key in ("roots", "nodes", "relations", "unknowns", "fingerprints", "evidenceContexts", "omittedUnknownOccurrences"):
                entries = projection.get(key)
                if isinstance(entries, list):
                    self.projection_counts[key] = len(entries)
            if type(projection.get("nodesTruncated")) is bool:
                self.projection_counts["nodes_truncated"] = projection["nodesTruncated"]

    def projection_complete(self) -> bool:
        return (
            self.projection_counts.get("nodes_truncated") is False
            and self.projection_counts.get("omittedUnknownOccurrences", 0) == 0
        )

    def metadata(self) -> dict[str, Any]:
        self.validate()
        worker_completed = (
            self.final_projection
            and not self.semantic_failure
            and not self.protocol_invalid
        )
        semantic_coverage_complete = (
            self.coverage is not None and self.coverage.get("status") == "complete"
        )
        projection_complete = self.projection_complete()
        return {
            "count": self.count,
            "bytes": self.bytes,
            "sha256": self.hashes,
            "hashes_truncated": self.count > len(self.hashes),
            "kinds": dict(self.kinds),
            "parse_errors": self.errors[:16],
            "worker_completed": worker_completed,
            "semantic_coverage_complete": semantic_coverage_complete,
            "projection_complete": projection_complete,
            "complete": worker_completed and semantic_coverage_complete and projection_complete,
            "semantic_failure": self.semantic_failure,
            "protocol_invalid": self.protocol_invalid,
            "final_projection": self.final_projection,
            "semantic_coverage": self.coverage,
            "projection_counts": self.projection_counts,
            "semantic_hashes": self.semantic_hashes,
            "encoding": self.encoding,
            "decoded_bytes": self.decoded_bytes,
            "decoded_sha256": self.decoded_sha256,
            "decoded_budget_bytes": MAX_DECODED_BYTES,
            "compressed_terminal_count": self.compressed_terminal_count,
            "decoded_frame_count": self.decoded_frame_count,
        }

    def close(self) -> None:
        self.spool.close()


class FamilySampler:
    def __init__(self, pid: int, started: float) -> None:
        self.root = psutil.Process(pid)
        self.root_identity = (pid, self.root.create_time())
        self.identities: dict[tuple[int, float], psutil.Process] = {}
        self.cpu_us: dict[tuple[int, float], int] = {}
        self.peak_rss = 0
        self.samples = 0
        self.started = started

    def sample(self) -> None:
        try:
            members = [self.root, *self.root.children(recursive=True)]
        except psutil.Error:
            members = []
        rss = 0
        for member in members:
            try:
                identity = (member.pid, member.create_time())
                self.identities[identity] = member
                rss += member.memory_info().rss
                times = member.cpu_times()
                self.cpu_us[identity] = max(self.cpu_us.get(identity, 0), int((times.user + times.system) * 1_000_000))
            except (psutil.Error, OSError):
                continue
        self.samples += 1
        self.peak_rss = max(self.peak_rss, rss)

    def cpu_total_us(self) -> int:
        return sum(self.cpu_us.values())


@dataclass
class WorkerMonitorState:
    frames: FrameAccumulator
    counters: dict[str, int]
    stderr_hash: Any


def identity_alive(identity: tuple[int, float]) -> bool:
    try:
        return psutil.Process(identity[0]).create_time() == identity[1]
    except (psutil.Error, OSError):
        return False


def cleanup_process(proc: subprocess.Popen[bytes], sampler: FamilySampler) -> list[str]:
    errors: list[str] = []
    try:
        sampler.sample()
    except Exception as exc:
        errors.append(f"sample-before-cleanup: {exc}")
    root_identity = sampler.root_identity
    if proc.poll() is None and identity_alive(root_identity):
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        except OSError as exc:
            errors.append(f"killpg-term: {exc}")
        deadline = time.monotonic() + CLEANUP_SECONDS
        while proc.poll() is None and time.monotonic() < deadline:
            time.sleep(0.02)
        if proc.poll() is None and identity_alive(root_identity):
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError as exc:
                errors.append(f"killpg-kill: {exc}")
    for identity, child in list(sampler.identities.items()):
        if identity == root_identity or not identity_alive(identity):
            continue
        try:
            os.kill(identity[0], signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError as exc:
            errors.append(f"child-{identity[0]}: {exc}")
    try:
        proc.wait(timeout=CLEANUP_SECONDS)
    except subprocess.TimeoutExpired:
        errors.append("root-wait-timeout")
    return errors


def worker_command(executable: Path) -> list[str]:
    return [str(executable), "--rea-javascript-worker", f"--rea-javascript-worker-max-heap-mb={MAX_HEAP_MB}"]


def build_worker_request(source: bytes, member: str, metadata: dict[str, Any]) -> bytes:
    request = {
        "max_heap_mb": MAX_HEAP_MB,
        "node_budget": NODE_BUDGET,
        "unknown_budget": UNKNOWN_BUDGET,
        "source": source.decode("utf-8"),
        "path": member,
        "file": {
            "path": member,
            "container_sha256": metadata["archive_sha256"],
            "sha256": metadata["sha256"],
            "bytes": metadata["bytes"],
            "inventory_artifact_id": f"artifact:benchmark:{member}",
            "kind": "javascript",
            "unpacked": False,
        },
    }
    return json.dumps(request, separators=(",", ":")).encode("utf-8") + b"\n"


def register_worker_streams(
    proc: subprocess.Popen[bytes],
    selector: selectors.BaseSelector,
) -> None:
    assert proc.stdin and proc.stdout and proc.stderr
    for stream, kind in ((proc.stdin, "stdin"), (proc.stdout, "stdout"), (proc.stderr, "stderr")):
        os.set_blocking(stream.fileno(), False)
        events = selectors.EVENT_WRITE if kind == "stdin" else selectors.EVENT_READ
        selector.register(stream, events, kind)


def monitor_worker(
    proc: subprocess.Popen[bytes],
    selector: selectors.BaseSelector,
    request: bytes,
    sampler: FamilySampler,
    state: WorkerMonitorState,
) -> tuple[str, str | None, str]:
    assert proc.stdin
    pending = memoryview(request)
    frames = state.frames
    counters = state.counters
    status = "incomplete"
    error: str | None = None
    sampler.sample()
    next_sample_at = time.monotonic() + FAMILY_SAMPLE_INTERVAL_SECONDS

    while selector.get_map():
        now = time.monotonic()
        elapsed = now - sampler.started
        if elapsed >= TIMEOUT_SECONDS:
            status, error = "timeout", "30-second worker deadline exceeded"
            break
        if now >= next_sample_at:
            sampler.sample()
            next_sample_at = now + FAMILY_SAMPLE_INTERVAL_SECONDS
        if sampler.peak_rss > MAX_FAMILY_RSS:
            status, error = "family-rss-cap", "4 GiB process-family RSS cap exceeded"
            break
        if counters["output"] >= MAX_OUTPUT_BYTES:
            status, error = "output-cap", "64 MiB worker output cap exceeded"
            break

        for key, events in selector.select(min(0.05, TIMEOUT_SECONDS - elapsed)):
            if key.data == "stdin":
                try:
                    written = os.write(key.fileobj.fileno(), pending)
                except BlockingIOError:
                    continue
                if written:
                    pending = pending[written:]
                if not pending:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                continue
            if not events & selectors.EVENT_READ:
                continue
            chunk = key.fileobj.read1(64 * 1024)
            if not chunk:
                selector.unregister(key.fileobj)
                key.fileobj.close()
                if key.data == "stdout":
                    frames.finish()
                continue
            if counters["output"] + len(chunk) > MAX_OUTPUT_BYTES:
                status, error = "output-cap", "64 MiB combined worker output cap exceeded"
                break
            counters["output"] += len(chunk)
            if key.data == "stdout":
                frames.feed(chunk)
            else:
                counters["stderr"] += len(chunk)
                state.stderr_hash.update(chunk)

        if status != "incomplete":
            break

        if proc.poll() is not None and pending:
            try:
                selector.unregister(proc.stdin)
            except (KeyError, ValueError):
                pass
            proc.stdin.close()
            pending = memoryview(b"")
        if proc.poll() is not None and not selector.get_map():
            break

    if status == "incomplete" and time.monotonic() - sampler.started >= TIMEOUT_SECONDS:
        status = "timeout"
        error = "30-second worker deadline exceeded"
    return status, error, state.stderr_hash.hexdigest()


def worker_completion(
    state: WorkerMonitorState,
    returncode: int | None,
) -> tuple[bool, bool, bool, bool]:
    worker_completed = (
        returncode == 0
        and state.frames.final_projection
        and not state.frames.semantic_failure
        and not state.frames.protocol_invalid
    )
    semantic_coverage_complete = (
        state.frames.coverage is not None
        and state.frames.coverage.get("status") == "complete"
    )
    projection_complete = state.frames.projection_complete()
    return (
        worker_completed,
        semantic_coverage_complete,
        projection_complete,
        worker_completed and semantic_coverage_complete and projection_complete,
    )


def close_worker_streams(
    proc: subprocess.Popen[bytes] | None,
    selector: selectors.BaseSelector | None,
) -> list[str]:
    errors: list[str] = []
    if proc is None:
        return errors
    for stream in (proc.stdin, proc.stdout, proc.stderr):
        if stream is None:
            continue
        try:
            stream.close()
        except OSError as exc:
            errors.append(f"close: {exc}")
    if selector is not None:
        selector.close()
    return errors


def run_worker(
    label: str,
    executable: Path,
    request: bytes,
    compare_semantic_fields: bool = False,
) -> dict[str, Any]:
    started = time.monotonic()
    state = WorkerMonitorState(
        frames=FrameAccumulator(compare_semantic_fields),
        counters={"output": 0, "stderr": 0},
        stderr_hash=hashlib.sha256(),
    )
    status = "incomplete"
    error: str | None = None
    stderr_digest = hashlib.sha256(b"").hexdigest()
    cleanup_errors: list[str] = []
    proc: subprocess.Popen[bytes] | None = None
    sampler: FamilySampler | None = None
    selector: selectors.BaseSelector | None = None
    worker_io_ms = 0.0
    cleanup_ms = 0.0
    protocol_validation_ms = 0.0

    try:
        proc = subprocess.Popen(
            worker_command(executable),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            env={key: value for key, value in os.environ.items() if key != "NODE_OPTIONS"},
        )
        sampler = FamilySampler(proc.pid, started)
        selector = selectors.DefaultSelector()
        register_worker_streams(proc, selector)
        status, error, stderr_digest = monitor_worker(
            proc,
            selector,
            request,
            sampler,
            state,
        )
    except (BrokenPipeError, OSError, ValueError) as exc:
        status, error = "protocol-error", str(exc)
        stderr_digest = state.stderr_hash.hexdigest()
    finally:
        cleanup_started = time.monotonic()
        worker_io_ms = (cleanup_started - started) * 1000
        if proc is not None and sampler is not None:
            cleanup_errors.extend(cleanup_process(proc, sampler))
        elif proc is not None:
            try:
                proc.wait(timeout=CLEANUP_SECONDS)
            except subprocess.TimeoutExpired:
                cleanup_errors.append("unowned-process-wait-timeout")
        cleanup_errors.extend(close_worker_streams(proc, selector))
        cleanup_ms = (time.monotonic() - cleanup_started) * 1000

    returncode = proc.returncode if proc is not None else None
    validation_started = time.monotonic()
    try:
        state.frames.validate()
        worker_completed, coverage_complete, projection_complete, complete = worker_completion(
            state,
            returncode,
        )
        frame_metadata = state.frames.metadata()
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        error = error or f"protocol-validation-error: {exc}"
        worker_completed = False
        coverage_complete = False
        projection_complete = False
        complete = False
        frame_metadata = {
            "count": state.frames.count,
            "bytes": state.frames.bytes,
            "protocol_invalid": True,
            "parse_errors": ["protocol-validation-error"],
        }
    finally:
        protocol_validation_ms = (time.monotonic() - validation_started) * 1000
        try:
            state.frames.close()
        except OSError as exc:
            cleanup_errors.append(f"frame-spool-close: {exc}")
    complete = complete and error is None and not cleanup_errors
    if cleanup_errors:
        status = "cleanup-error"
    elif complete:
        status = "complete"
    elif worker_completed and error is None:
        status = "partial" if not coverage_complete else "protocol-complete"
    elif status == "incomplete":
        status = f"exit-{returncode}"
    frame_metadata["worker_completed"] = worker_completed
    frame_metadata["complete"] = complete
    return {
        "label": label,
        "executable": str(executable),
        "elapsed_ms": round((time.monotonic() - started) * 1000, 3),
        "worker_io_ms": round(worker_io_ms, 3),
        "cleanup_ms": round(cleanup_ms, 3),
        "protocol_validation_ms": round(protocol_validation_ms, 3),
        "returncode": returncode,
        "status": status,
        "worker_completed": worker_completed,
        "semantic_coverage_complete": coverage_complete,
        "projection_complete": projection_complete,
        "complete": complete,
        "error": error,
        "stdout_stderr_bytes": state.counters["output"],
        "stderr_bytes": state.counters["stderr"],
        "stderr_sha256": stderr_digest,
        "frames": frame_metadata,
        "sample_count": sampler.samples if sampler is not None else 0,
        "sampled_family_peak_rss_bytes": sampler.peak_rss if sampler is not None else 0,
        "sampled_family_cpu_us": sampler.cpu_total_us() if sampler is not None else 0,
        "cleanup_errors": cleanup_errors,
        "measurement_note": "Worker I/O wall includes launch and pipe draining. Total wall also includes cleanup and deferred protocol validation. CPU and RSS are sampled family lower bounds at a 50 ms cadence; receipt stores protocol hashes and metadata only.",
    }

def prepare_fixtures(args: argparse.Namespace) -> list[tuple[Fixture, str, bytes, dict[str, Any]]]:
    fixtures = load_fixtures(args.figma_asar, args.postman_asar, args.fixture)
    prepared = []
    for fixture in fixtures:
        member, source, _, metadata = read_asar_member(
            fixture.archive,
            fixture.requested_member,
        )
        expected = EXPECTED.get(fixture.name)
        if expected and (metadata["bytes"], metadata["sha256"]) != expected:
            raise ValueError(
                f"{fixture.name} fixture digest or length differs from the qualified archive"
            )
        prepared.append((fixture, member, source, metadata))
    return prepared


def run_rounds(
    prepared: list[tuple[Fixture, str, bytes, dict[str, Any]]],
    baseline: Path,
    candidate: Path,
    rounds: int,
    candidate_only: bool,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for round_number in range(1, rounds + 1):
        for fixture, member, source, metadata in prepared:
            if candidate_only:
                order = [("candidate", candidate)]
            elif round_number % 2:
                order = [("baseline", baseline), ("candidate", candidate)]
            else:
                order = [("candidate", candidate), ("baseline", baseline)]
            request = build_worker_request(source, member, metadata)
            for label, executable in order:
                result = run_worker(
                    f"{fixture.name}#round-{round_number}",
                    executable,
                    request,
                )
                results.append(
                    {
                        "round": round_number,
                        "fixture": fixture.name,
                        "member": member,
                        "source_sha256": metadata["sha256"],
                        "order": label,
                        "result": result,
                    }
                )
    return results


def build_receipt(
    baseline: Path,
    candidate: Path,
    candidate_only: bool,
    rounds: int,
    prepared: list[tuple[Fixture, str, bytes, dict[str, Any]]],
    results: list[dict[str, Any]],
    started_at: str,
) -> dict[str, Any]:
    return {
        "schema": "rea-js-worker-comparison-v2",
        "started_at_utc": started_at,
        "finished_at_utc": now_utc(),
        "provenance": benchmark_provenance(),
        "config": {
            "baseline": str(baseline),
            "candidate": str(candidate),
            "baseline_sha256": sha256_file(baseline),
            "candidate_sha256": sha256_file(candidate),
            "candidate_only": candidate_only,
            "rounds": rounds,
            "timeout_seconds": TIMEOUT_SECONDS,
            "max_heap_mb": MAX_HEAP_MB,
            "node_budget": NODE_BUDGET,
            "unknown_budget": UNKNOWN_BUDGET,
            "max_family_rss_bytes": MAX_FAMILY_RSS,
            "max_combined_output_bytes": MAX_OUTPUT_BYTES,
        },
        "fixtures": [
            {"name": fixture.name, "archive": str(fixture.archive), "member": member, "metadata": metadata}
            for fixture, member, _, metadata in prepared
        ],
        "results": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument(
        "--candidate-only",
        action="store_true",
        help="Run only the candidate for protocol smoke tests.",
    )
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--figma-asar", type=Path, default=DEFAULT_FIGMA)
    parser.add_argument("--postman-asar", type=Path, default=DEFAULT_POSTMAN)
    parser.add_argument("--fixture", type=Path, action="append", default=[])
    args = parser.parse_args()
    if args.rounds < 1:
        parser.error("--rounds must be positive")
    if args.baseline is None and not args.candidate_only:
        parser.error("--baseline is required unless --candidate-only is set")

    baseline = args.baseline or args.candidate
    prepared = prepare_fixtures(args)
    started_at = now_utc()
    results = run_rounds(
        prepared,
        baseline,
        args.candidate,
        args.rounds,
        args.candidate_only,
    )
    receipt = build_receipt(
        baseline,
        args.candidate,
        args.candidate_only,
        args.rounds,
        prepared,
        results,
        started_at,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(receipt, indent=2) + "\n")
    print(
        json.dumps(
            {
                "output": str(args.output),
                "results": len(results),
                "complete": sum(r["result"]["complete"] for r in results),
            }
        )
    )
    return 0 if results and all(r["result"]["complete"] for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
