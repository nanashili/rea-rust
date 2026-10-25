#!/usr/bin/env python3
"""Assemble the native release layout consumed by the installer and CLI."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import tomllib
import zipfile

from skill_bundle import stage_skill


ROOT = Path(__file__).resolve().parents[2]
TARGETS = (
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "aarch64-unknown-linux-gnu",
    "x86_64-unknown-linux-gnu",
    "x86_64-pc-windows-msvc",
)
SEMVER = re.compile(
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
)


def release_version():
    with (ROOT / "crates/apps/rea/Cargo.toml").open("rb") as manifest:
        version = tomllib.load(manifest)["package"]["version"]
    match = SEMVER.fullmatch(version)
    if match is None:
        raise ValueError(f"invalid package SemVer: {version}")
    prerelease = match.group(4)
    if prerelease and any(
        item.isdigit() and len(item) > 1 and item.startswith("0")
        for item in prerelease.split(".")
    ):
        raise ValueError(f"invalid numeric prerelease identifier: {version}")
    return version


def source_commit():
    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("release source must have a full Git commit identity")
    return commit


def copy_executable(source, destination):
    if source.is_symlink() or not source.is_file() or not os.access(source, os.X_OK):
        raise ValueError(f"missing executable build output: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(0o755)


def stage_release(destination, target, rea, worker):
    suffix = ".exe" if target.endswith("-windows-msvc") else ""
    copy_executable(rea, destination / f"bin/rea{suffix}")
    copy_executable(worker, destination / f"bin/rea-ghidra-rust-worker{suffix}")
    for name in ("LICENSE", "README.md"):
        shutil.copyfile(ROOT / name, destination / name)
    version = release_version()
    (destination / "VERSION").write_text(version + "\n")
    stage_skill(ROOT, destination)

    files = {}
    for path in sorted(destination.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"release contents must not contain symlinks: {path}")
        if path.is_file():
            with path.open("rb") as content:
                files[path.relative_to(destination).as_posix()] = hashlib.file_digest(
                    content, "sha256"
                ).hexdigest()
    manifest = {
        "name": "rea-rust",
        "schema_version": 1,
        "version": version,
        "target": target,
        "source_commit": source_commit(),
        "files": files,
    }
    (destination / "release.json").write_text(json.dumps(manifest, indent=2) + "\n")


def write_tar_archive(destination, archive_path):
    with tarfile.open(archive_path, "w:gz", format=tarfile.USTAR_FORMAT) as archive:
        for path in sorted(destination.rglob("*")):
            relative = path.relative_to(destination)
            info = archive.gettarinfo(str(path), arcname=f"rea-rust/{relative.as_posix()}")
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mtime = 0
            if path.is_file():
                info.mode = 0o755 if relative.parts[0] == "bin" else 0o644
                with path.open("rb") as content:
                    archive.addfile(info, content)
            else:
                info.mode = 0o755
                archive.addfile(info)


def write_zip_archive(destination, archive_path):
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(destination.rglob("*")):
            if not path.is_file():
                continue
            relative = path.relative_to(destination)
            info = zipfile.ZipInfo(f"rea-rust/{relative.as_posix()}")
            info.compress_type = zipfile.ZIP_DEFLATED
            mode = 0o755 if relative.parts[0] == "bin" else 0o644
            info.external_attr = (0o100000 | mode) << 16
            with path.open("rb") as content, archive.open(info, "w") as member:
                shutil.copyfileobj(content, member)


def archive_release(destination, output):
    """Publish an archive only after every staged member has been written."""
    with tempfile.TemporaryDirectory(prefix=".rea-release-", dir=output.parent) as temporary:
        archive_path = Path(temporary) / output.name
        if output.suffix == ".zip":
            write_zip_archive(destination, archive_path)
        else:
            write_tar_archive(destination, archive_path)
        # Exclusive hard-link creation refuses to overwrite an earlier artifact.
        os.link(archive_path, output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=TARGETS)
    parser.add_argument("--output-dir", type=Path, default=Path("dist"))
    parser.add_argument("--rea", type=Path)
    parser.add_argument("--worker", type=Path)
    parser.add_argument("--validate-tag")
    options = parser.parse_args()

    if options.validate_tag is not None:
        expected = "v" + release_version()
        if options.validate_tag != expected:
            parser.error(f"release tag must match the rea package version: {expected}")
        print(f"Validated {expected}")
        return
    if options.target is None:
        parser.error("--target is required when packaging")

    output_directory = options.output_dir.resolve()
    output_directory.mkdir(parents=True, exist_ok=True)
    is_windows = options.target.endswith("-windows-msvc")
    archive_extension = ".zip" if is_windows else ".tar.gz"
    executable_suffix = ".exe" if is_windows else ""
    output = output_directory / f"rea-rust-{options.target}{archive_extension}"
    rea = options.rea or ROOT / f"target/{options.target}/release/rea{executable_suffix}"
    worker = options.worker or ROOT / (
        f"ghidra-rust-worker/target/{options.target}/release/rea-ghidra-rust-worker{executable_suffix}"
    )
    with tempfile.TemporaryDirectory(prefix="rea-release-stage-") as temporary:
        destination = Path(temporary) / "rea-rust"
        destination.mkdir()
        stage_release(destination, options.target, rea, worker)
        archive_release(destination, output)
    print(output)


if __name__ == "__main__":
    main()
