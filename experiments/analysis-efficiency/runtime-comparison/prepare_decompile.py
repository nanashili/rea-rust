#!/usr/bin/env python3
"""Freeze and build the native Ghidra worker for the decompilation benchmark.

This preparation step deliberately owns a separate output directory.  It only
reads the existing runtime preparation and source checkout, and records enough
identity information to make reuse of the resulting worker reviewable.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
from datetime import datetime, timezone
from typing import Any


DEFAULT_GHIDRA = Path("/Users/tihan-nico/Developer/Tools/ghidra_12.1.4_PUBLIC")
TARGET_DIR = Path("/tmp/rea-target-shared")
WORKER_RELATIVE = Path("native/ghidra-rust-worker")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def run_capture(command: list[str], cwd: Path | None = None) -> dict[str, Any]:
    completed = subprocess.run(
        command,
        cwd=cwd,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=build_environment(),
    )
    return {"command": command, "output": completed.stdout.strip()}


def build_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment["LC_ALL"] = "C"
    environment["CARGO_TARGET_DIR"] = str(TARGET_DIR)
    return environment


def git_value(repository: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=build_environment(),
    )
    return result.stdout.strip()


def source_manifest(root: Path, exclusions: set[str] | None = None) -> list[dict[str, Any]]:
    excluded = exclusions or set()
    entries: list[dict[str, Any]] = []
    for directory, directory_names, file_names in os.walk(root, followlinks=False):
        directory_path = Path(directory)
        directory_names[:] = sorted(
            name for name in directory_names
            if name not in excluded and not (directory_path == root and name in {"target"})
        )
        for name in sorted(file_names):
            if name == ".DS_Store":
                continue
            path = directory_path / name
            relative = path.relative_to(root)
            if path.is_symlink():
                raise RuntimeError(f"symlink is not allowed in frozen source: {path}")
            if not path.is_file():
                continue
            entries.append({
                "path": relative.as_posix(),
                "bytes": path.stat().st_size,
                "sha256": digest_file(path),
                "mode": stat.S_IMODE(path.stat().st_mode),
            })
    return entries


def manifest_digest(entries: list[dict[str, Any]]) -> str:
    encoded = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
    return digest_bytes(encoded)


def copy_tree(source: Path, destination: Path) -> None:
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(destination)
    shutil.copytree(
        source,
        destination,
        symlinks=False,
        ignore=shutil.ignore_patterns(".git", "target", "node_modules"),
    )


def inspect_local_dependencies(worker: Path) -> dict[str, Any]:
    import tomllib

    manifests: list[dict[str, Any]] = []
    local_paths: list[dict[str, str]] = []
    for path in sorted(worker.rglob("Cargo.toml")):
        document = tomllib.loads(path.read_text())
        manifests.append({"path": path.relative_to(worker).as_posix(), "sha256": digest_file(path)})
        for section_name in ("dependencies", "dev-dependencies", "build-dependencies"):
            for name, specification in document.get(section_name, {}).items():
                if isinstance(specification, dict) and "path" in specification:
                    dependency = (path.parent / specification["path"]).resolve()
                    if not dependency.is_relative_to(worker.resolve()):
                        raise RuntimeError(
                            f"local Cargo dependency escapes worker snapshot: {path} -> {dependency}"
                        )
                    local_paths.append({
                        "manifest": path.relative_to(worker).as_posix(),
                        "name": name,
                        "path": dependency.relative_to(worker.resolve()).as_posix(),
                    })
    return {"manifests": manifests, "local_paths": local_paths}


def cargo_lock_identity(worker: Path) -> dict[str, Any]:
    lock = worker / "Cargo.lock"
    import tomllib

    document = tomllib.loads(lock.read_text())
    packages = []
    for package in document.get("package", []):
        packages.append({
            "name": package.get("name"),
            "version": package.get("version"),
            "source": package.get("source"),
            "checksum": package.get("checksum"),
        })
    return {
        "sha256": digest_file(lock),
        "packages": packages,
    }


def refuse_live_builds() -> None:
    result = subprocess.run(
        ["ps", "-axo", "pid=,comm=,args="],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    current_pid = str(os.getpid())
    active: list[str] = []
    for line in result.stdout.splitlines():
        fields = line.strip().split(None, 2)
        if len(fields) < 2 or fields[0] == current_pid:
            continue
        executable = Path(fields[1]).name.lower()
        if executable in {"cargo", "rustc"}:
            active.append(fields[1])
    if active:
        raise RuntimeError("refusing worker build while cargo/rustc processes are active")


def host_identity() -> dict[str, Any]:
    return {
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "python": sys.version.split()[0],
        "commands": {
            "uname": run_capture(["uname", "-a"]),
            "model": run_capture(["sysctl", "-n", "hw.model"]) if shutil.which("sysctl") else None,
            "cpu": run_capture(["sysctl", "-n", "hw.ncpu"]) if shutil.which("sysctl") else None,
            "memory": run_capture(["sysctl", "-n", "hw.memsize"]) if shutil.which("sysctl") else None,
            "sw_vers": run_capture(["sw_vers"]) if shutil.which("sw_vers") else None,
        },
    }


def ghidra_identity(install: Path) -> dict[str, Any]:
    properties = install / "Ghidra" / "application.properties"
    if not properties.is_file():
        raise FileNotFoundError(properties)
    values: dict[str, str] = {}
    for line in properties.read_text().splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    system = platform.system().lower()
    machine = platform.machine().lower()
    platform_key = {
        ("darwin", "arm64"): "mac_arm_64",
        ("darwin", "x86_64"): "mac_x86_64",
        ("linux", "x86_64"): "linux_x86_64",
        ("linux", "aarch64"): "linux_arm_64",
    }.get((system, machine))
    if not platform_key:
        raise RuntimeError(f"unsupported Ghidra platform: {system}/{machine}")
    decompiler = install / "Ghidra" / "Features" / "Decompiler" / "os" / platform_key / "decompile"
    files = [
        properties,
        install / "support" / "analyzeHeadless",
        install / "support" / "LaunchSupport.jar",
        install / "Ghidra" / "Framework" / "Utility" / "lib" / "Utility.jar",
        decompiler,
    ]
    manifest = []
    for path in files:
        if not path.is_file():
            raise FileNotFoundError(path)
        manifest.append({"path": str(path.relative_to(install)), "bytes": path.stat().st_size, "sha256": digest_file(path)})
    java = shutil.which("java")
    if not java:
        raise RuntimeError("java is required to record the Ghidra runtime")
    java_path = Path(java).resolve()
    java_version = run_capture([str(java_path), "--version"])
    java_properties = run_capture([str(java_path), "-XshowSettings:properties", "-version"])
    java_home_match = re.search(r"^\s*java\.home\s*=\s*(.+)$", java_properties["output"], re.MULTILINE)
    if java_home_match is None:
        raise RuntimeError("selected Java did not report java.home")
    java_home = Path(java_home_match.group(1).strip()).resolve()
    launch_java = java_home / "bin" / ("java.exe" if platform.system() == "Windows" else "java")
    if not launch_java.is_file():
        raise FileNotFoundError(launch_java)
    return {
        "install_dir": str(install),
        "application": {
            "version": values.get("application.version"),
            "java_min": values.get("application.java.min"),
            "java_max": values.get("application.java.max"),
            "properties_sha256": digest_file(properties),
        },
        "java": {
            "path": str(java_path),
            "bytes": java_path.stat().st_size,
            "sha256": digest_file(java_path),
            "version": java_version,
        },
        "java_home": str(java_home),
        "launch_java": {
            "path": str(launch_java),
            "bytes": launch_java.stat().st_size,
            "sha256": digest_file(launch_java),
        },
        "platform_key": platform_key,
        "manifest": manifest,
        "manifest_sha256": manifest_digest(manifest),
    }


def engine_identity() -> dict[str, Any]:
    """Record the pure-Rust decompiler source that is compiled into the worker."""
    registry_root = Path.home() / ".cargo" / "registry" / "src"
    candidates = sorted(registry_root.glob("*/ghidra-decompiler-2.1.0"))
    if len(candidates) != 1:
        raise RuntimeError("expected exactly one installed ghidra-decompiler-2.1.0 source")
    crate = candidates[0]
    files = [crate / "README.md", crate / "Cargo.toml", crate / "Cargo.toml.orig", crate / ".cargo_vcs_info.json"]
    embedded_source = crate / "src" / "embedded_languages.rs"
    references = re.findall(r'include_bytes!\("([^\"]+)"\)', embedded_source.read_text())
    embedded = []
    for reference in references:
        path = (embedded_source.parent / reference).resolve()
        if not path.is_file() or not path.is_relative_to(crate.resolve()):
            raise RuntimeError(f"invalid embedded language asset: {reference}")
        embedded.append({
            "path": path.relative_to(crate).as_posix(),
            "bytes": path.stat().st_size,
            "sha256": digest_file(path),
        })
    manifest = []
    for path in files + [embedded_source]:
        manifest.append({"path": path.relative_to(crate).as_posix(), "bytes": path.stat().st_size, "sha256": digest_file(path)})
    return {
        "crate": "ghidra-decompiler",
        "version": "2.1.0",
        "source_root": str(crate),
        "upstream_git_sha": json.loads((crate / ".cargo_vcs_info.json").read_text())["git"]["sha1"],
        "upstream_description": "pure Rust port of the Ghidra 12.2 C++ decompiler; no Java/C++ runtime dependency",
        "manifest": manifest,
        "embedded_languages": embedded,
        "embedded_manifest_sha256": manifest_digest(embedded),
    }


def run_logged(command: list[str], cwd: Path, log_path: Path) -> dict[str, Any]:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("w") as log:
        log.write("$ " + " ".join(command) + "\n")
        log.flush()
        completed = subprocess.run(
            command,
            cwd=cwd,
            stdout=log,
            stderr=subprocess.STDOUT,
            env=build_environment(),
        )
    return {
        "command": command,
        "log": str(log_path),
        "returncode": completed.returncode,
        "log_sha256": digest_file(log_path),
    }


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepared", type=Path, required=True, help="frozen runtime preparation")
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ghidra-install-dir", type=Path, default=DEFAULT_GHIDRA)
    parser.add_argument("--build", action="store_true", help="build the frozen worker")
    return parser.parse_args()


def prepared_identity(prepared: Path) -> dict[str, Any]:
    provenance = prepared / "provenance.json"
    binary = prepared / "bin" / "rea"
    if not provenance.is_file() or not binary.is_file():
        raise RuntimeError(f"prepared runtime lacks provenance or binary: {prepared}")
    return {
        "root": str(prepared),
        "provenance_sha256": digest_file(provenance),
        "binary": {"path": str(binary), "sha256": digest_file(binary), "bytes": binary.stat().st_size},
    }


def main() -> int:
    args = parse_arguments()
    repository = args.repository.resolve()
    prepared = args.prepared.resolve()
    output = args.output.resolve()
    if not repository.is_dir() or not prepared.is_dir():
        raise RuntimeError("repository and prepared runtime must be directories")
    if output.exists():
        raise RuntimeError(f"output already exists: {output}")
    output.mkdir(parents=True)

    worker_source = repository / WORKER_RELATIVE
    if not worker_source.is_dir():
        raise RuntimeError(f"worker source is missing: {worker_source}")
    local_dependencies = inspect_local_dependencies(worker_source)
    native_root = repository / "native"
    source_entries = source_manifest(worker_source, {".git", "target", "node_modules"})
    worker_snapshot = output / "worker-source"
    copy_tree(worker_source, worker_snapshot)
    copied_entries = source_manifest(worker_snapshot, {".git", "target", "node_modules"})
    if source_entries != copied_entries:
        raise RuntimeError("worker source changed during snapshot")
    source_record = {
        "root": str(worker_snapshot),
        "entries": copied_entries,
        "aggregate_sha256": manifest_digest(copied_entries),
        "git": {
            "repository": str(native_root),
            "head": git_value(native_root, "rev-parse", "HEAD"),
            "tree": git_value(native_root, "rev-parse", "HEAD^{tree}"),
            "worker_tree_at_head": git_value(native_root, "rev-parse", "HEAD:ghidra-rust-worker"),
            "worker_status": git_value(native_root, "status", "--short", "--", "ghidra-rust-worker"),
        },
        "cargo_local_dependencies": local_dependencies,
        "cargo_lock": cargo_lock_identity(worker_source),
    }
    write_json(output / "worker-source-manifest.json", source_record)
    engine = engine_identity()
    write_json(output / "engine-identity.json", engine)

    bin_dir = output / "bin"
    bin_dir.mkdir()
    os.symlink(prepared / "bin" / "rea", bin_dir / "rea")
    provenance: dict[str, Any] = {
        "schema": "rea-ghidra-decompile-preparation-v1",
        "status": "snapshot_complete",
        "started_at_utc": utc_now(),
        "repository": str(repository),
        "prepared_runtime": prepared_identity(prepared),
        "worker_source": {
            "snapshot": str(worker_snapshot),
            "manifest": str(output / "worker-source-manifest.json"),
            "aggregate_sha256": source_record["aggregate_sha256"],
            "git": source_record["git"],
            "cargo_local_dependencies": source_record["cargo_local_dependencies"],
            "cargo_lock": source_record["cargo_lock"],
        },
        "ghidra": ghidra_identity(args.ghidra_install_dir.resolve()),
        "engine": {
            "identity": str(output / "engine-identity.json"),
            "crate": engine["crate"],
            "version": engine["version"],
            "upstream_git_sha": engine["upstream_git_sha"],
            "embedded_manifest_sha256": engine["embedded_manifest_sha256"],
        },
        "host": host_identity(),
        "toolchain": {
            "cargo": run_capture(["cargo", "+1.93.1", "--version"]),
            "rustc": run_capture(["rustc", "+1.93.1", "--version"]),
        },
        "build": {"requested": args.build, "target_dir": str(TARGET_DIR)},
    }
    write_json(output / "provenance.json", provenance)

    if args.build:
        refuse_live_builds()
        build = run_logged(
            ["cargo", "+1.93.1", "build", "--locked", "--release", "--manifest-path", str(worker_snapshot / "Cargo.toml")],
            repository,
            output / "worker-build.log",
        )
        provenance["build"]["command"] = build
        if build["returncode"]:
            provenance["status"] = "build_failed"
            provenance["failure"] = build
            write_json(output / "provenance.json", provenance)
            raise RuntimeError(f"worker build failed; see {output / 'worker-build.log'}")
        built = TARGET_DIR / "release" / "rea-ghidra-rust-worker"
        if not built.is_file():
            provenance["status"] = "build_failed"
            provenance["failure"] = {"reason": "expected worker executable missing", "path": str(built)}
            write_json(output / "provenance.json", provenance)
            raise RuntimeError(f"worker executable missing: {built}")
        worker_binary = bin_dir / "rea-ghidra-rust-worker"
        shutil.copy2(built, worker_binary)
        worker_binary.chmod(worker_binary.stat().st_mode | stat.S_IXUSR)
        provenance["build"]["executable"] = {
            "path": str(worker_binary),
            "bytes": worker_binary.stat().st_size,
            "sha256": digest_file(worker_binary),
        }
        provenance["status"] = "complete"
        provenance["finished_at_utc"] = utc_now()
        write_json(output / "provenance.json", provenance)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"prepare_decompile.py: {error}", file=sys.stderr)
        raise
