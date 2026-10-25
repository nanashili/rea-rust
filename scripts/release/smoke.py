#!/usr/bin/env python3
"""Smoke-test one packaged REA release on the runner that built it.

This is intentionally an end-to-end check.  It does not import REA internals:
the archive is unpacked into a temporary directory and all checks go through
the shipped executable and worker.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from typing import Any


SEMVER = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
MAX_OUTPUT = 2 * 1024 * 1024
MAX_MCP_LINE = 8 * 1024 * 1024


class SmokeFailure(RuntimeError):
    """A release invariant was not satisfied."""


def fail(message: str) -> None:
    raise SmokeFailure(message)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    return parser.parse_args()


def safe_member_path(name: str) -> Path:
    path = Path(name)
    if path.is_absolute() or ".." in path.parts:
        fail(f"archive contains unsafe path: {name!r}")
    if not path.parts or path.parts[0] != "rea-rust":
        fail(f"archive member is outside rea-rust/: {name!r}")
    return path


def unpack_archive(archive: Path, destination: Path) -> Path:
    if not archive.is_file():
        fail(f"archive does not exist: {archive}")

    root = destination / "rea-rust"
    with tarfile.open(archive, "r:gz") as bundle:
        members = bundle.getmembers()
        if not members:
            fail("archive is empty")
        for member in members:
            path = safe_member_path(member.name)
            if member.issym() or member.islnk() or member.isdev() or not (
                member.isdir() or member.isfile()
            ):
                fail(f"archive member is not a regular file or directory: {member.name!r}")
            target = destination / path
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            source = bundle.extractfile(member)
            if source is None:
                fail(f"archive file cannot be read: {member.name!r}")
            with source, target.open("wb") as output:
                shutil.copyfileobj(source, output)
            target.chmod(member.mode & 0o777)
    if not root.is_dir():
        fail("archive does not contain the rea-rust/ top-level directory")
    return root


def read_release_metadata(root: Path) -> tuple[str, dict[str, Any]]:
    version_text = (root / "VERSION").read_text(encoding="utf-8").strip()
    if not SEMVER.fullmatch(version_text):
        fail(f"invalid VERSION value: {version_text!r}")
    try:
        manifest = json.loads((root / "release.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"invalid release.json: {error}")
    if not isinstance(manifest, dict) or manifest.get("name") != "rea-rust":
        fail("release.json has the wrong package name")
    if manifest.get("schema_version") != 1 or manifest.get("version") != version_text:
        fail("release.json schema/version does not match VERSION")
    target = manifest.get("target")
    if not isinstance(target, str) or not target:
        fail("release.json target is missing")
    source_commit = manifest.get("source_commit")
    if not isinstance(source_commit, str) or not re.fullmatch(r"[0-9a-f]{40}", source_commit):
        fail("release.json source_commit is not a 40-character SHA-1")
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        fail("release.json files map is missing")
    for name, digest in files.items():
        path = safe_member_path(f"rea-rust/{name}")
        relative = path.relative_to("rea-rust")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            fail(f"invalid SHA-256 for {name!r}")
        file_path = root / relative
        if not file_path.is_file():
            fail(f"manifest file is missing: {name!r}")
        actual = hashlib.sha256(file_path.read_bytes()).hexdigest()
        if actual != digest:
            fail(f"manifest hash mismatch for {name!r}")
    return version_text, manifest


def run(command: list[str], *, cwd: Path, env: dict[str, str], timeout: float) -> subprocess.CompletedProcess[str]:
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        terminate_process_group(process)
        fail(f"command timed out after {timeout:.0f}s: {' '.join(command)}")
    result = subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
    if len(result.stdout) > MAX_OUTPUT or len(result.stderr) > MAX_OUTPUT:
        fail(f"command produced excessive output: {' '.join(command)}")
    return result


def terminate_process_group(process: subprocess.Popen[str]) -> None:
    """Terminate a timed-out command and any provider children it owns."""
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            return
        process.wait(timeout=5)


def require_success(result: subprocess.CompletedProcess[str], description: str) -> None:
    if result.returncode:
        fail(
            f"{description} failed with exit {result.returncode}\n"
            f"stdout: {result.stdout[-4000:]}\nstderr: {result.stderr[-4000:]}"
        )


def verify_cli(
    binary: Path,
    version: str,
    release_root: Path,
    cwd: Path,
    env: dict[str, str],
) -> None:
    result = run([str(binary), "--version"], cwd=cwd, env=env, timeout=20)
    require_success(result, "rea --version")
    if version not in result.stdout and version not in result.stderr:
        fail(f"rea --version did not report {version}: {result.stdout!r}")
    require_success(run([str(binary), "--help"], cwd=cwd, env=env, timeout=20), "rea --help")

    require_success(
        run([str(binary), "--verify-installation"], cwd=cwd, env=env, timeout=20),
        "rea --verify-installation",
    )

    manifest_path = release_root / "release.json"
    original_manifest = manifest_path.read_text(encoding="utf-8")
    try:
        manifest = json.loads(original_manifest)
        manifest["name"] = "foreign-package"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        rejected = run([str(binary), "--verify-installation"], cwd=cwd, env=env, timeout=20)
        if rejected.returncode == 0:
            fail("rea --verify-installation accepted a foreign package manifest")
    finally:
        manifest_path.write_text(original_manifest, encoding="utf-8")


class McpConnection:
    """Own one MCP subprocess and its line-oriented transport threads."""

    def __init__(self, binary: Path, root: Path, env: dict[str, str]) -> None:
        self.command = [str(binary), "mcp"]
        self.process = subprocess.Popen(
            self.command,
            cwd=root,
            env=env,
            text=True,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        self.stdout_queue: queue.Queue[tuple[str, str | None]] = queue.Queue()
        self.stderr_chunks: list[str] = []
        self.stdout_thread = threading.Thread(target=self._read_stdout, daemon=True)
        self.stderr_thread = threading.Thread(target=self._read_stderr, daemon=True)
        self.stdout_thread.start()
        self.stderr_thread.start()

    def _read_stdout(self) -> None:
        assert self.process.stdout is not None
        for line in self.process.stdout:
            self.stdout_queue.put(("line", line))
        self.stdout_queue.put(("eof", None))

    def _read_stderr(self) -> None:
        assert self.process.stderr is not None
        while True:
            chunk = self.process.stderr.read(65536)
            if not chunk:
                return
            if sum(map(len, self.stderr_chunks)) < MAX_OUTPUT:
                remaining = MAX_OUTPUT + 1 - sum(map(len, self.stderr_chunks))
                self.stderr_chunks.append(chunk[:remaining])

    def __enter__(self) -> "McpConnection":
        return self

    def __exit__(self, exception_type: object, exception: object, traceback: object) -> None:
        cleanup_error: BaseException | None = None
        try:
            if self.process.stdin is not None and not self.process.stdin.closed:
                self.process.stdin.close()
            self.process.wait(timeout=15)
        except (OSError, subprocess.TimeoutExpired) as error:
            cleanup_error = error
            terminate_process_group(self.process)
        finally:
            self.stdout_thread.join(timeout=5)
            self.stderr_thread.join(timeout=5)

        if exception is None and cleanup_error is not None:
            fail(f"MCP stdio server did not shut down cleanly: {cleanup_error}")

    def send(self, request: dict[str, Any]) -> None:
        if self.process.stdin is None or self.process.stdin.closed:
            fail("MCP stdin closed before the request was sent")
        try:
            self.process.stdin.write(json.dumps(request) + "\n")
            self.process.stdin.flush()
        except (BrokenPipeError, OSError) as error:
            fail(f"MCP stdio exchange failed: {error}")

    def receive_response(self, request_id: int) -> dict[str, Any]:
        deadline = time.monotonic() + 45.0
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                fail(f"MCP did not reply to request {request_id}")
            try:
                kind, line = self.stdout_queue.get(timeout=remaining)
            except queue.Empty:
                fail(f"MCP did not reply to request {request_id}")
            if kind == "eof":
                fail(f"MCP stdout closed before request {request_id} was answered")
            assert line is not None
            if len(line) > MAX_MCP_LINE:
                fail("MCP emitted an excessively large JSON line")
            try:
                reply = json.loads(line)
            except json.JSONDecodeError as error:
                fail(f"MCP emitted non-JSON stdout: {line[:200]!r} ({error})")
            if not isinstance(reply, dict):
                fail(f"MCP emitted a non-object response: {reply!r}")
            if reply.get("id") == request_id:
                return reply

    def stderr(self) -> str:
        return "".join(self.stderr_chunks)


def mcp_exchange(binary: Path, root: Path, env: dict[str, str]) -> None:
    with McpConnection(binary, root, env) as connection:
        connection.send(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "rea-release-smoke", "version": "1"},
                },
            }
        )
        initialize = connection.receive_response(1)

        connection.send({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
        connection.send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        tools_reply = connection.receive_response(2)

        connection.send(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "binary_session", "arguments": {}},
            }
        )
        call_reply = connection.receive_response(3)

    stderr = connection.stderr()
    if len(stderr) > MAX_OUTPUT:
        fail("MCP emitted excessive stderr")
    result = subprocess.CompletedProcess(connection.command, connection.process.returncode, "", stderr)
    require_success(result, "MCP stdio")
    for request_id, reply in ((1, initialize), (2, tools_reply), (3, call_reply)):
        if "error" in reply:
            fail(f"MCP request {request_id} failed: {reply['error']}")
    initialize_result = initialize.get("result", {})
    if initialize_result.get("protocolVersion") != "2025-11-25":
        fail(f"MCP negotiated an unexpected protocol version: {initialize!r}")
    if not initialize_result.get("serverInfo", {}).get("name"):
        fail("MCP initialize response omitted serverInfo")
    tools = tools_reply.get("result", {}).get("tools", [])
    if not any(tool.get("name") == "binary_session" for tool in tools):
        fail("MCP tools/list did not advertise binary_session")
    if not isinstance(call_reply.get("result"), dict):
        fail("MCP binary_session returned no structured result")
    if call_reply["result"].get("isError") is True:
        fail(f"MCP binary_session returned an error: {call_reply['result']!r}")
    if not isinstance(call_reply["result"].get("structuredContent"), dict):
        fail("MCP binary_session did not return structured content")


def compile_fixture(directory: Path, env: dict[str, str]) -> Path:
    compiler = shutil.which("cc", path=env.get("PATH"))
    if compiler is None:
        fail("release smoke requires a C compiler named cc")
    source = directory / "smoke_fixture.c"
    binary = directory / "smoke_fixture"
    source.write_text("int main(void) { return 42; }\n", encoding="utf-8")
    require_success(
        run(
            [compiler, "-O0", "-g", "-o", str(binary), str(source)],
            cwd=directory,
            env=env,
            timeout=30,
        ),
        "compile Ghidra smoke fixture",
    )
    return binary


def verify_ghidra(binary: Path, root: Path, env: dict[str, str], work: Path) -> None:
    fixture = compile_fixture(work, env)
    search = run(
        [
            str(binary),
            "search",
            str(fixture),
            "main",
            "--kind",
            "procedures",
            "--provider",
            "ghidra-rust",
            "--json",
        ],
        cwd=root,
        env=env,
        timeout=180,
    )
    require_success(search, "Ghidra Rust procedure search")
    try:
        search_output = json.loads(search.stdout)
    except json.JSONDecodeError as error:
        fail(f"Ghidra procedure search did not return JSON: {error}")
    if search_output.get("provider", {}).get("id") != "ghidra-rust":
        fail(f"Ghidra procedure search reported the wrong provider: {search_output!r}")
    procedures = search_output.get("normalized_result")
    if not isinstance(procedures, list) or not procedures:
        fail(f"Ghidra procedure search returned no functions: {search_output!r}")
    selector = procedures[0].get("value")
    if not isinstance(selector, str) or not selector:
        fail(f"Ghidra procedure search returned an invalid selector: {search_output!r}")

    result = run(
        [
            str(binary),
            "decompile",
            str(fixture),
            selector,
            "--provider",
            "ghidra-rust",
            "--json",
        ],
        cwd=root,
        env=env,
        timeout=180,
    )
    require_success(result, "Ghidra Rust decompile")
    try:
        output = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        fail(f"Ghidra decompile did not return JSON: {error}")
    if (
        not isinstance(output, dict)
        or output.get("ok") is False
        or output.get("status") == "failed"
        or output.get("error")
    ):
        fail(f"Ghidra decompile returned a failure: {output!r}")
    if output.get("provider", {}).get("id") != "ghidra-rust":
        fail(f"Ghidra decompile reported the wrong provider: {output!r}")
    pseudocode = output.get("normalized_result")
    if not isinstance(pseudocode, str) or not pseudocode.strip():
        fail(f"Ghidra decompile returned no pseudocode: {output!r}")


def verify_setup_plan(binary: Path, root: Path, env: dict[str, str]) -> None:
    config_path = root / ".codex" / "config.toml"
    result = run(
        [str(binary), "setup", "--dry-run", "--client", "codex", "--json"],
        cwd=root,
        env=env,
        timeout=30,
    )
    require_success(result, "native setup dry-run")
    try:
        output = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        fail(f"setup dry-run did not return JSON: {error}")
    if output.get("status") != "planned":
        fail(f"setup dry-run did not return a plan: {output!r}")
    if config_path.exists():
        fail("setup dry-run wrote Codex configuration")


def verify_registration(binary: Path, root: Path, env: dict[str, str]) -> None:
    command = f"{binary} mcp"
    result = run(
        [str(binary), "mcp", "add", "--command", command, "--agent", "codex", "--no-global", "--json"],
        cwd=root,
        env=env,
        timeout=30,
    )
    require_success(result, "MCP registration")
    try:
        output = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        fail(f"MCP registration did not return JSON: {error}")
    if output.get("status") != "ready":
        fail(f"MCP registration was not ready: {output!r}")
    config_path = root / ".codex" / "config.toml"
    if not config_path.is_file():
        fail("MCP registration did not create the isolated Codex configuration")
    config = config_path.read_text(encoding="utf-8")
    if str(binary) not in config or 'args = ["mcp"]' not in config:
        fail(f"Codex configuration does not contain the native launcher:\n{config}")
    if any(token in config.lower() for token in ("npm", "npx", "node")):
        fail("native MCP registration wrote an npm/Node launcher")


def main() -> int:
    arguments = parse_args()
    with tempfile.TemporaryDirectory(prefix="rea-release-smoke-") as temporary:
        work = Path(temporary)
        root = unpack_archive(arguments.archive.resolve(), work / "unpacked")
        version, _manifest = read_release_metadata(root)
        binary = root / "bin" / "rea"
        worker = root / "bin" / "rea-ghidra-rust-worker"
        if not binary.is_file() or not os.access(binary, os.X_OK):
            fail("archive does not contain an executable bin/rea")
        if not worker.is_file() or not os.access(worker, os.X_OK):
            fail("archive does not contain an executable Ghidra worker")

        isolated_home = work / "home"
        isolated_home.mkdir()
        isolated_cwd = work / "cwd"
        isolated_cwd.mkdir()
        env = os.environ.copy()
        env.update(
            {
                "HOME": str(isolated_home),
                "XDG_CONFIG_HOME": str(isolated_home / ".config"),
                "XDG_DATA_HOME": str(isolated_home / ".local" / "share"),
                "XDG_CACHE_HOME": str(isolated_home / ".cache"),
            }
        )
        for key in list(env):
            if key.startswith("REA_"):
                env.pop(key)
        for key in (
            "CODEX_HOME",
            "CLAUDE_CONFIG_DIR",
            "GEMINI_CLI_HOME",
            "REACONFIG",
        ):
            env.pop(key, None)
        compiler = shutil.which("cc")
        if compiler is None:
            fail("release smoke requires a C compiler named cc")
        env["PATH"] = os.pathsep.join(
            dict.fromkeys((str(Path(compiler).parent), "/usr/bin", "/bin"))
        )
        verify_cli(binary, version, root, isolated_cwd, env)
        mcp_exchange(binary, isolated_cwd, env)
        verify_setup_plan(binary, isolated_cwd, env)
        verify_registration(binary, isolated_cwd, env)
        verify_ghidra(binary, isolated_cwd, env, work)
    print(f"release smoke passed: {arguments.archive} ({version})")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SmokeFailure as error:
        print(f"release smoke failed: {error}", file=sys.stderr)
        raise SystemExit(1)
