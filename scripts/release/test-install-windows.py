#!/usr/bin/env python3
"""Black-box checks for the Windows installer.

The checks run on the Windows release runner.  They use a tiny managed fixture
executable and a local Invoke-WebRequest shim, so no GitHub release is needed.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import zipfile


ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "install.ps1"
TARGET = "x86_64-pc-windows-msvc"
VERSION = "6.7.0"


def powershell() -> str:
    for command in ("pwsh", "powershell"):
        if shutil.which(command):
            return command
    raise RuntimeError("PowerShell is required")


def run_powershell(script: str, environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
    with tempfile.NamedTemporaryFile("w", suffix=".ps1", delete=False, encoding="utf-8") as handle:
        handle.write(script)
        path = Path(handle.name)
    try:
        return subprocess.run(
            [powershell(), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(path)],
            env={**os.environ, **environment},
            text=True,
            capture_output=True,
            check=False,
        )
    finally:
        path.unlink(missing_ok=True)


def make_fake_executable(directory: Path) -> None:
    script = f'''
$source = @"
using System;
public static class FakeRea {{
    public static int Main(string[] args) {{
        if (args.Length == 1 && args[0] == "--version") {{ Console.WriteLine("{VERSION}"); return 0; }}
        if (args.Length == 1 && args[0] == "--verify-installation") {{ Console.WriteLine("rea {VERSION} installation verified"); return 0; }}
        return 0;
    }}
}}
"@
Add-Type -TypeDefinition $source -OutputType ConsoleApplication -OutputAssembly (Join-Path $env:REA_FIXTURE 'fake.exe')
'''
    command = shutil.which("powershell.exe") or shutil.which("powershell")
    if not command:
        raise RuntimeError("Windows PowerShell 5.1 is required to compile the fixture")
    with tempfile.NamedTemporaryFile("w", suffix=".ps1", delete=False, encoding="utf-8") as handle:
        handle.write(script)
        script_path = Path(handle.name)
    try:
        result = subprocess.run(
            [command, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(script_path)],
            env={**os.environ, "REA_FIXTURE": str(directory)},
            text=True,
            capture_output=True,
            check=False,
        )
    finally:
        script_path.unlink(missing_ok=True)
    if result.returncode:
        raise AssertionError(result.stdout + result.stderr)


def make_archive(fixture: Path) -> Path:
    root = fixture / "rea-rust"
    (root / "bin").mkdir(parents=True)
    shutil.copy2(fixture / "fake.exe", root / "bin/rea.exe")
    shutil.copy2(fixture / "fake.exe", root / "bin/rea-ghidra-rust-worker.exe")
    (root / "VERSION").write_text(VERSION + "\n", encoding="utf-8")
    (root / "LICENSE").write_text("fixture\n", encoding="utf-8")
    (root / "README.md").write_text("fixture\n", encoding="utf-8")
    (root / "release.json").write_text(
        '{"name":"rea-rust","schema_version":1,"version":"6.7.0",'
        '"target":"x86_64-pc-windows-msvc","source_commit":"'
        + "0" * 40
        + '","files":{}}\n',
        encoding="utf-8",
    )
    archive = fixture / f"rea-rust-{TARGET}.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as output:
        for path in sorted(root.rglob("*")):
            if path.is_file():
                output.write(path, Path("rea-rust") / path.relative_to(root))
    checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
    (fixture / "SHA256SUMS").write_text(f"{checksum} *{archive.name}\n", encoding="ascii")
    return archive


def installer_script() -> str:
    return f'''
function Invoke-WebRequest {{
    param([string] $Uri, [string] $OutFile)
    Copy-Item -LiteralPath (Join-Path $env:REA_FIXTURE ([System.IO.Path]::GetFileName($Uri))) -Destination $OutFile
}}
. '{INSTALLER}'
'''


def main() -> int:
    if os.name != "nt":
        print("Windows installer tests require Windows; skipped")
        return 0
    with tempfile.TemporaryDirectory(prefix="rea-rust-windows-test-") as temporary:
        fixture = Path(temporary) / "fixture"
        fixture.mkdir()
        make_fake_executable(fixture)
        make_archive(fixture)
        install_root = Path(temporary) / "install root"
        bin_dir = Path(temporary) / "bin directory"
        environment = {
            "REA_FIXTURE": str(fixture),
            "REA_INSTALL_ROOT": str(install_root),
            "REA_BIN_DIR": str(bin_dir),
            "REA_VERSION": VERSION,
        }
        success = run_powershell(installer_script(), environment)
        if success.returncode:
            raise AssertionError(success.stdout + success.stderr)
        launcher = bin_dir / "rea.cmd"
        if not launcher.is_file() or VERSION not in launcher.read_text(encoding="utf-8"):
            raise AssertionError("installer did not create the stable launcher")
        repeat = run_powershell(installer_script(), environment)
        if repeat.returncode:
            raise AssertionError("repeat installation failed: " + repeat.stderr)

        launcher.write_text("@echo off\necho foreign\n", encoding="utf-8")
        foreign = run_powershell(installer_script(), environment)
        if foreign.returncode == 0 or "unowned launcher" not in foreign.stderr:
            raise AssertionError("foreign launcher was not rejected")
        launcher.unlink()
        restored = run_powershell(installer_script(), environment)
        if restored.returncode:
            raise AssertionError("launcher restoration failed: " + restored.stderr)

        launcher.unlink()
        launcher.mkdir()
        activation = run_powershell(installer_script(), environment)
        if activation.returncode == 0:
            raise AssertionError("launcher directory was accepted during activation")
        launcher.rmdir()
        restored = run_powershell(installer_script(), environment)
        if restored.returncode:
            raise AssertionError("launcher recreation failed: " + restored.stderr)

        installed_executable = next((install_root / "versions").rglob("rea.exe"))
        installed_executable.write_bytes(installed_executable.read_bytes() + b"tampered")
        tampered = run_powershell(installer_script(), environment)
        if tampered.returncode == 0 or "contents differ" not in tampered.stderr:
            raise AssertionError("tampered installation was not rejected")

        junction_root = Path(temporary) / "junction install"
        junction_versions = junction_root / "versions"
        junction_versions.mkdir(parents=True)
        junction_target = Path(temporary) / "junction target"
        junction_target.mkdir()
        junction = junction_versions / VERSION
        junction_result = subprocess.run(
            ["cmd.exe", "/c", "mklink", "/J", str(junction), str(junction_target)],
            text=True,
            capture_output=True,
            check=False,
        )
        if junction_result.returncode == 0:
            junction_environment = {**environment, "REA_INSTALL_ROOT": str(junction_root), "REA_BIN_DIR": str(junction_root / "bin")}
            rejected = run_powershell(installer_script(), junction_environment)
            if rejected.returncode == 0 or "reparse" not in rejected.stderr.lower():
                raise AssertionError("version-directory junction was not rejected")

        (fixture / "SHA256SUMS").write_text("0" * 64 + f" *rea-rust-{TARGET}.zip\n", encoding="ascii")
        failed = run_powershell(installer_script(), environment)
        if failed.returncode == 0 or not launcher.is_file():
            raise AssertionError("checksum failure did not preserve the active launcher")
    print("Windows installer checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
