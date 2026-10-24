#!/usr/bin/env python3
"""Freeze reproducible TypeScript and native runtime inputs.

Snapshotting is the default. Compilation is opt-in and serialized with other
builds using this checkout.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

DEFAULT_BASELINE = "833136507dd79d959340b09862a53af344e4f1b3"
EXCLUDED_PARTS = {".git", "target", "node_modules", "ghidra-rust-worker"}


def run(command: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(command, cwd=cwd, env=env, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(command)}\n{result.stderr}")
    return result.stdout.strip()


def optional_command(command: list[str], cwd: Path) -> dict[str, object]:
    result = subprocess.run(command, cwd=cwd, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, check=False)
    return {"command": command, "returncode": result.returncode,
            "stdout": result.stdout.strip(), "stderr": result.stderr.strip()}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def manifest(root: Path, files: list[Path]) -> list[dict[str, object]]:
    rows = []
    for path in sorted(files):
        rows.append({"path": path.relative_to(root).as_posix(), "bytes": path.stat().st_size,
                     "sha256": sha256(path)})
    return rows


def manifest_digest(rows: list[dict[str, object]]) -> str:
    encoded = json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def native_files(root: Path) -> list[Path]:
    files = []
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        if path.is_symlink() or not path.is_file() or relative.parts[0] in EXCLUDED_PARTS:
            continue
        files.append(path)
    return files


def typescript_files(root: Path) -> list[Path]:
    return [path for path in root.rglob("*")
            if path.is_file() and "node_modules" not in path.relative_to(root).parts
            and path.relative_to(root).parts[0] != "dist"]


def support_files(repository: Path) -> list[Path]:
    files = []
    for relative_root in (Path("bridge/native"), Path("bridge/android")):
        root = repository / relative_root
        if not root.is_dir():
            continue
        files.extend(path for path in root.rglob("*") if path.is_file() and not path.is_symlink())
    return files


def snapshot_support(repository: Path, output: Path) -> list[dict[str, object]]:
    source_files = support_files(repository)
    source_rows = manifest(repository, source_files)
    for source in source_files:
        destination = output / source.relative_to(repository)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    snapshot_rows = manifest(output, [output / row["path"] for row in source_rows])
    if source_rows != manifest(repository, support_files(repository)) or source_rows != snapshot_rows:
        raise RuntimeError("bridge support source changed during snapshot")
    return source_rows


def package_lock(root: Path) -> dict[str, object]:
    return json.loads((root / "package-lock.json").read_text())


def dependency_install_info(typescript: Path) -> dict[str, object]:
    installed_path = typescript / "node_modules" / ".package-lock.json"
    if not installed_path.is_file():
        raise RuntimeError(f"installed dependency lockfile not found: {installed_path}")
    root_lock = package_lock(typescript)
    installed_lock = json.loads(installed_path.read_text())
    root_package = root_lock.get("packages", {}).get("", {})
    direct = {
        **root_package.get("dependencies", {}),
        **root_package.get("devDependencies", {}),
    }
    installed_packages = installed_lock.get("packages", {})
    direct_versions = {
        name: {
            "expected": root_lock.get("packages", {}).get(f"node_modules/{name}", {}).get("version"),
            "installed": installed_packages.get(f"node_modules/{name}", {}).get("version"),
        }
        for name in sorted(direct)
    }
    return {
        "node_modules_reused_symlink": True,
        "node_modules_target": str((typescript / "node_modules").resolve()),
        "installed_package_lock_sha256": sha256(installed_path),
        "direct_dependency_versions": direct_versions,
    }


def verify_lock(repository: Path, typescript: Path, baseline: str,
                *, compare_checkout: bool = True) -> dict[str, object]:
    snapshot = package_lock(typescript)
    baseline_lock = json.loads(run(["git", "show", f"{baseline}:package-lock.json"], cwd=repository))
    if snapshot != baseline_lock:
        raise RuntimeError("archived package-lock.json differs from its baseline ref")
    keys = ("name", "version", "lockfileVersion", "requires", "packages")
    checkout = package_lock(repository)
    checkout_equal = {key: checkout.get(key) for key in keys} == {
        key: baseline_lock.get(key) for key in keys
    }
    if compare_checkout and not checkout_equal:
        raise RuntimeError("checkout package-lock dependency sections differ from baseline")
    return {"baseline_sha256": sha256(typescript / "package-lock.json"),
            "checkout_sha256": sha256(repository / "package-lock.json"),
            "dependency_sections_equal": checkout_equal}


def extract_archive(repository: Path, ref: str, destination: Path) -> None:
    result = subprocess.run(["git", "archive", "--format=tar", ref], cwd=repository,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode:
        raise RuntimeError(f"git archive failed: {result.stderr.decode(errors='replace')}")
    with tempfile.NamedTemporaryFile(prefix="rea-baseline-", suffix=".tar") as handle:
        handle.write(result.stdout)
        handle.flush()
        with tarfile.open(handle.name) as source:
            source.extractall(destination, filter="data")


def command_versions(node: Path, repository: Path) -> dict[str, str]:
    npm = node.with_name("npm")
    cargo = shutil.which("cargo")
    rustc = shutil.which("rustc")
    versions = {"node": run([str(node), "--version"], cwd=repository), "node_sha256": sha256(node)}
    if npm.exists():
        versions["npm"] = run([str(npm), "--version"], cwd=repository)
    tsc = repository / "node_modules" / "typescript" / "bin" / "tsc"
    if tsc.is_file():
        versions["typescript"] = run([str(node), str(tsc), "--version"], cwd=repository)
    if cargo:
        versions["cargo"] = run([cargo, "+1.93.1", "--version"], cwd=repository)
    if rustc:
        versions["rustc"] = run([rustc, "+1.93.1", "--version"], cwd=repository)
    return versions


def host_details(repository: Path) -> dict[str, object]:
    details = {"system": platform.system(), "release": platform.release(),
               "machine": platform.machine(), "processor": platform.processor()}
    if details["system"] == "Darwin":
        for command in (["sw_vers"], ["sysctl", "-n", "hw.model"],
                        ["sysctl", "-n", "hw.ncpu"], ["sysctl", "-n", "hw.memsize"]):
            details[" ".join(command)] = optional_command(command, repository)
    return details


def refuse_live_builds() -> None:
    listing = subprocess.run(["ps", "-axo", "pid=,comm=,args="], text=True,
                             stdout=subprocess.PIPE, check=False).stdout
    active = []
    for line in listing.splitlines():
        fields = line.strip().split(None, 2)
        if len(fields) != 3:
            continue
        executable = fields[1].rsplit("/", 1)[-1]
        arguments = fields[2].split()
        if executable == "rustc" or (
            executable in {"cargo", "npm", "node"}
            and {"build", "check", "test", "compile"}.intersection(arguments)
        ):
            active.append(line.strip())
    if active:
        raise RuntimeError("refusing build while another build appears active: " + active[0])


def build(command: list[str], cwd: Path, environment: dict[str, str], log: Path) -> None:
    with log.open("w") as output:
        process = subprocess.run(command, cwd=cwd, env=environment, stdout=output,
                                 stderr=subprocess.STDOUT, check=False)
    if process.returncode:
        raise RuntimeError(f"build failed; see {log}")


def snapshot_typescript(repository: Path, output: Path, baseline: str) -> dict[str, object]:
    typescript = output / "typescript"
    typescript.mkdir()
    extract_archive(repository, baseline, typescript)
    lock_info = verify_lock(repository, typescript, baseline)
    node_modules = repository / "node_modules"
    if not node_modules.is_dir():
        raise RuntimeError("checkout node_modules is required for the TypeScript snapshot")
    (typescript / "node_modules").symlink_to(node_modules, target_is_directory=True)
    rows = manifest(typescript, typescript_files(typescript))
    return {"lock": lock_info, "install": dependency_install_info(typescript),
            "manifest": rows, "manifest_sha256": manifest_digest(rows)}


def snapshot_native(repository: Path, output: Path) -> tuple[list[dict[str, object]], Path]:
    source_root = repository / "native"
    snapshot_root = output / "native"
    snapshot_root.mkdir()
    source_rows = manifest(source_root, native_files(source_root))
    for source in native_files(source_root):
        destination = snapshot_root / source.relative_to(source_root)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    if source_rows != manifest(source_root, native_files(source_root)):
        raise RuntimeError("native source changed during snapshot")
    if source_rows != manifest(snapshot_root, native_files(snapshot_root)):
        raise RuntimeError("native snapshot differs from source")
    return source_rows, snapshot_root


def git_state(repository: Path, baseline: str) -> dict[str, str]:
    return {
        "repository_head": run(["git", "rev-parse", "HEAD"], cwd=repository),
        "repository_tree": run(["git", "rev-parse", "HEAD^{tree}"], cwd=repository),
        "repository_status": run(["git", "status", "--porcelain=v1"], cwd=repository),
        "baseline_ref": baseline,
        "baseline_commit": run(["git", "rev-parse", baseline], cwd=repository),
        "baseline_tree": run(["git", "rev-parse", f"{baseline}^{{tree}}"], cwd=repository),
        "native_head": run(["git", "rev-parse", "HEAD"], cwd=repository / "native"),
        "native_tree": run(["git", "rev-parse", "HEAD^{tree}"], cwd=repository / "native"),
        "native_status": run(["git", "status", "--porcelain=v1"], cwd=repository / "native"),
    }


def build_typescript(node: Path, typescript: Path, output: Path) -> dict[str, object]:
    npm = node.with_name("npm")
    if not npm.exists():
        raise RuntimeError(f"pinned npm not found beside --node: {npm}")
    environment = os.environ.copy()
    environment["PATH"] = str(node.parent) + os.pathsep + environment.get("PATH", "")
    build([str(node), "scripts/check-dependency-install.mjs"], typescript, environment,
          output / "typescript-dependency-check.log")
    build([str(npm), "run", "compile"], typescript, environment, output / "typescript-build.log")
    dist = typescript / "dist"
    metadata = list(dist.rglob("*recordedCatalogDigests*")) if dist.is_dir() else []
    if not dist.is_dir() or not any(dist.iterdir()) or not metadata:
        raise RuntimeError("compile completed without dist or recorded catalog metadata")
    rows = manifest(typescript, [path for path in dist.rglob("*") if path.is_file()])
    return {"manifest": rows, "manifest_sha256": manifest_digest(rows)}


def build_native(native: Path, output: Path) -> dict[str, object]:
    environment = os.environ.copy()
    environment["CARGO_TARGET_DIR"] = "/tmp/rea-target-shared"
    cargo = shutil.which("cargo") or "cargo"
    command = [cargo, "+1.93.1", "build", "--locked", "--release", "-p", "rea",
               "--manifest-path", str(native / "Cargo.toml")]
    build(command, native, environment, output / "native-build.log")
    executable = Path(environment["CARGO_TARGET_DIR"]) / "release" / "rea"
    if not executable.is_file():
        raise RuntimeError(f"native build did not produce {executable}")
    binary = output / "bin" / "rea"
    binary.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(executable, binary)
    return {"path": str(binary), "bytes": binary.stat().st_size, "sha256": sha256(binary)}


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n")


def load_resume(repository: Path, output: Path, baseline: str) -> tuple[dict[str, object], Path]:
    provenance_path = output / "provenance.json"
    manifest_path = output / "native-source-manifest.json"
    if not provenance_path.is_file() or not manifest_path.is_file():
        raise RuntimeError("--resume requires provenance.json and native-source-manifest.json")
    provenance = json.loads(provenance_path.read_text())
    native = output / "native"
    if not native.is_dir() or not (output / "typescript").is_dir():
        raise RuntimeError("--resume requires frozen native and TypeScript snapshots")
    expected_native = json.loads(manifest_path.read_text())
    if manifest(native, native_files(native)) != expected_native:
        raise RuntimeError("native snapshot manifest changed; refusing --resume")
    checkout_rows = manifest(repository / "native", native_files(repository / "native"))
    typescript_manifest_path = output / "typescript-source-manifest.json"
    if not typescript_manifest_path.is_file():
        raise RuntimeError("--resume requires typescript-source-manifest.json")
    expected_typescript = json.loads(typescript_manifest_path.read_text())
    if manifest(output / "typescript", typescript_files(output / "typescript")) != expected_typescript:
        raise RuntimeError("TypeScript snapshot manifest changed; refusing --resume")
    support_manifest_path = output / "bridge-support-source-manifest.json"
    if not support_manifest_path.is_file():
        support_rows = snapshot_support(repository, output)
        write_json(support_manifest_path, support_rows)
    expected_support = json.loads(support_manifest_path.read_text())
    support_snapshot = [output / row["path"] for row in expected_support]
    if manifest(output, support_snapshot) != expected_support:
        raise RuntimeError("bridge support snapshot changed; refusing --resume")
    provenance["bridge_support_manifest_sha256"] = manifest_digest(expected_support)
    provenance["bridge_support_current_source_equal"] = (
        manifest(repository, support_files(repository)) == expected_support
    )
    lock_info = verify_lock(repository, output / "typescript", baseline, compare_checkout=False)
    provenance["typescript_installation"] = dependency_install_info(output / "typescript")
    provenance["resume_validation"] = {
        "checkout_native_manifest_sha256": manifest_digest(checkout_rows),
        "checkout_native_source_still_equal": checkout_rows == expected_native,
        "checkout_package_lock_dependency_sections_equal": lock_info["dependency_sections_equal"],
    }
    return provenance, native


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--baseline-ref", default=DEFAULT_BASELINE)
    parser.add_argument("--node", type=Path, required=True)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--build-typescript", action="store_true")
    parser.add_argument("--build-native", action="store_true")
    args = parser.parse_args()
    repository, output, node = args.repository.resolve(), args.output.resolve(), args.node.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise RuntimeError("--repository must be a Git checkout")
    if not node.is_absolute() or not os.access(node, os.X_OK):
        raise RuntimeError("--node must be an executable absolute path")
    if output.exists() and not args.resume:
        raise RuntimeError("--output must name a new directory (or use --resume)")

    if args.resume:
        provenance, native = load_resume(repository, output, args.baseline_ref)
        if provenance.get("git", {}).get("baseline_ref") != args.baseline_ref:
            raise RuntimeError("--resume baseline ref differs from the frozen provenance")
        write_json(output / "provenance.json", provenance)
    else:
        output.mkdir(parents=True)
        typescript_info = snapshot_typescript(repository, output, args.baseline_ref)
        source_rows, native = snapshot_native(repository, output)
        support_rows = snapshot_support(repository, output)
        write_json(output / "native-source-manifest.json", source_rows)
        write_json(output / "typescript-source-manifest.json", typescript_info.pop("manifest"))
        write_json(output / "bridge-support-source-manifest.json", support_rows)
        provenance = {
            "schema_version": 1,
            "commands": {
                "archive": ["git", "archive", "--format=tar", args.baseline_ref],
                "typescript_dependency_check": [str(node), "scripts/check-dependency-install.mjs"],
                "typescript_build": [str(node.with_name("npm")), "run", "compile"],
                "typescript_check": [str(node), "node_modules/typescript/bin/tsc", "--noEmit"],
                "native_check": ["cargo", "+1.93.1", "check", "--locked", "-p", "rea",
                                 "--manifest-path", str(native / "Cargo.toml")],
                "native_build": ["cargo", "+1.93.1", "build", "--locked", "--release", "-p", "rea",
                                 "--manifest-path", str(native / "Cargo.toml")],
            },
            "git": git_state(repository, args.baseline_ref),
            "host": host_details(repository),
            "toolchains": command_versions(node, repository),
            "typescript_package_lock": typescript_info["lock"],
            "typescript_installation": typescript_info["install"],
            "build_profiles": {
                "typescript": {"source": "git-archive", "profile": "compile", "features": []},
                "native": {"source": "native-snapshot", "profile": "release", "features": [],
                            "locked": True},
            },
            "typescript_source_manifest_sha256": typescript_info["manifest_sha256"],
            "native_source_manifest_sha256": manifest_digest(source_rows),
            "bridge_support_manifest_sha256": manifest_digest(support_rows),
            "builds_requested": {"typescript": args.build_typescript, "native": args.build_native},
            "builds": {},
        }
        write_json(output / "provenance.json", provenance)

    if args.build_typescript or args.build_native:
        refuse_live_builds()
    for name, requested, action in (
        ("typescript", args.build_typescript,
         lambda: build_typescript(node, output / "typescript", output)),
        ("native", args.build_native, lambda: build_native(native, output)),
    ):
        if not requested:
            continue
        try:
            result = action()
            provenance["builds"][name] = {"status": "complete", "result": result}
        except Exception as error:
            provenance["builds"][name] = {"status": "failed", "error": str(error)}
            write_json(output / "provenance.json", provenance)
            raise
        write_json(output / "provenance.json", provenance)
    return 0


if __name__ == "__main__":
    sys.exit(main())

