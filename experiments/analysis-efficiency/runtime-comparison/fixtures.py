#!/usr/bin/env python3
"""Generate deterministic, independently checkable runtime-comparison fixtures.

This module deliberately does not invoke either REA implementation.  It owns
fixture bytes and the small independent checks used by the benchmark runner.
The ELF and cargo-auditable encodings are written here rather than obtained
from the implementation under test, so a parser bug cannot manufacture its
own oracle.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
import struct
import subprocess
import zlib
from pathlib import Path
from typing import Any


PACKAGE_COUNT = 25_000
SMALL_PACKAGE_COUNT = 1
SQLITE_ROW_COUNT = 10_000
FIXTURE_ORACLE_REVISION = "runtime-comparison-fixtures-v3"
DEP_OFFSET = 512
ELF_HEADER_SIZE = 64
SECTION_HEADER_SIZE = 64
SECTION_TABLE_OFFSET = 128
SECTION_NAME_OFFSET = 384


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _manifest_entry(path: Path, *, source: str | None = None) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "path": path.name,
        "bytes": path.stat().st_size,
        "sha256": _sha256(path),
    }
    if source is not None:
        entry["source"] = source
    return entry


def _u16(buffer: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<H", buffer, offset, value)


def _u32(buffer: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<I", buffer, offset, value)


def _u64(buffer: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<Q", buffer, offset, value)


def _auditable_document(package_count: int) -> bytes:
    packages: list[dict[str, Any]] = []
    for index in range(package_count):
        package: dict[str, Any] = {
            "name": f"fixture-package-{index:05d}",
            "version": "1.0.0",
            "source": "registry+https://example.invalid/index",
        }
        if index == 0:
            package["root"] = True
        else:
            package["dependencies"] = [index - 1]
        packages.append(package)
    return json.dumps(
        # 99 is intentionally an unknown revision.  Readers must preserve the
        # numeric revision while reporting that its interpretation is limited.
        {"format": 99, "packages": packages},
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _elf64_with_dep_v0(document: bytes, *, section_name: str = ".dep-v0") -> bytes:
    compressed = zlib.compress(document, level=9)
    names = b"\0.shstrtab\0" + section_name.encode("ascii") + b"\0.rodata\0"
    name_dep = names.index(section_name.encode("ascii"))
    name_rodata = names.index(b".rodata")
    section_table_end = SECTION_TABLE_OFFSET + 4 * SECTION_HEADER_SIZE
    names_offset = max(SECTION_NAME_OFFSET, section_table_end)
    dep_offset = DEP_OFFSET
    rodata_offset = dep_offset + len(compressed)
    total = max(rodata_offset + 16, names_offset + len(names))
    image = bytearray(total)

    # ELF64 little-endian header.  The section table is sufficient for the
    # offline reader; no program headers or executable code are required.
    image[:7] = b"\x7fELF\x02\x01\x01"
    _u16(image, 16, 2)  # ET_EXEC
    _u16(image, 18, 0x3E)  # x86_64
    _u32(image, 20, 1)
    _u64(image, 40, SECTION_TABLE_OFFSET)
    _u16(image, 52, ELF_HEADER_SIZE)
    _u16(image, 54, 0)
    _u16(image, 56, 0)
    _u16(image, 58, SECTION_HEADER_SIZE)
    _u16(image, 60, 4)
    _u16(image, 62, 1)

    image[names_offset : names_offset + len(names)] = names
    image[dep_offset : dep_offset + len(compressed)] = compressed
    image[rodata_offset : rodata_offset + 16] = b"fixture-rodata\0\0"

    # Null, .shstrtab, .dep-v0 and .rodata section headers.
    shstr = SECTION_TABLE_OFFSET + SECTION_HEADER_SIZE
    _u32(image, shstr, 1)
    _u32(image, shstr + 4, 3)
    _u64(image, shstr + 24, names_offset)
    _u64(image, shstr + 32, len(names))
    dep = SECTION_TABLE_OFFSET + 2 * SECTION_HEADER_SIZE
    _u32(image, dep, name_dep)
    _u32(image, dep + 4, 1)
    _u64(image, dep + 24, dep_offset)
    _u64(image, dep + 32, len(compressed))
    rodata = SECTION_TABLE_OFFSET + 3 * SECTION_HEADER_SIZE
    _u32(image, rodata, name_rodata)
    _u32(image, rodata + 4, 1)
    _u64(image, rodata + 8, 2)
    _u64(image, rodata + 24, rodata_offset)
    _u64(image, rodata + 32, 16)
    return bytes(image)


def _write_sqlite(path: Path) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            "CREATE TABLE settings(key TEXT NOT NULL, value TEXT NOT NULL, revision INTEGER NOT NULL)"
        )
        connection.executemany(
            "INSERT INTO settings(key, value, revision) VALUES (?, ?, ?)",
            ((f"setting-{index:05d}", f"value-{index:05d}", index) for index in range(SQLITE_ROW_COUNT)),
        )
        connection.commit()
    finally:
        connection.close()


def _go_version_oracle(gofmt: Path) -> dict[str, Any]:
    go = shutil.which("go")
    if go is None:
        raise RuntimeError("installed go tool is required for the gofmt oracle")
    result = subprocess.run(
        [go, "version", "-m", str(gofmt)],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode:
        raise RuntimeError(f"go version -m failed: {result.stderr.strip()}")
    path = None
    settings: list[dict[str, str]] = []
    for line in result.stdout.splitlines()[1:]:
        fields = line.strip("\n").split("\t", 2)
        if len(fields) != 3 or fields[0] != "":
            continue
        _, kind, value = fields
        if kind == "path":
            path = value
        elif kind == "build":
            key, separator, setting_value = value.partition("=")
            if separator:
                settings.append({"key": key, "value": setting_value})
    return {
        "command": [go, "version", "-m", str(gofmt)],
        "stdout": result.stdout,
        "stderr": result.stderr,
        "go_tool": go,
        "path": path,
        "settings": settings,
    }


def _independent_dep_check(path: Path, expected_count: int) -> dict[str, Any]:
    data = path.read_bytes()
    if data[:7] != b"\x7fELF\x02\x01\x01":
        raise AssertionError("fixture is not ELF64 little-endian")
    section_offset = struct.unpack_from("<Q", data, 40)[0]
    section_size = struct.unpack_from("<H", data, 58)[0]
    section_count = struct.unpack_from("<H", data, 60)[0]
    names_index = struct.unpack_from("<H", data, 62)[0]
    if section_size != 64 or section_count != 4 or names_index != 1:
        raise AssertionError("unexpected ELF section table")
    names_header = section_offset + names_index * section_size
    names_start, names_bytes = struct.unpack_from("<QQ", data, names_header + 24)
    names = data[names_start : names_start + names_bytes]
    dep_header = section_offset + 2 * section_size
    name_index = struct.unpack_from("<I", data, dep_header)[0]
    dep_start, dep_bytes = struct.unpack_from("<QQ", data, dep_header + 24)
    if names[name_index:].split(b"\0", 1)[0] != b".dep-v0":
        raise AssertionError("dependency section name is not .dep-v0")
    compressed = data[dep_start : dep_start + dep_bytes]
    decoder = zlib.decompressobj()
    inflated = decoder.decompress(compressed) + decoder.flush()
    if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
        raise AssertionError("dependency section is not one complete zlib member")
    document = json.loads(inflated)
    packages = document.get("packages")
    if document.get("format") != 99 or not isinstance(packages, list):
        raise AssertionError("unexpected auditable document")
    if len(packages) != expected_count:
        raise AssertionError(f"expected {expected_count} packages, got {len(packages)}")
    for index, package in enumerate(packages):
        expected = {
            "name": f"fixture-package-{index:05d}",
            "version": "1.0.0",
            "source": "registry+https://example.invalid/index",
        }
        if index == 0:
            expected["root"] = True
        else:
            expected["dependencies"] = [index - 1]
        if package != expected:
            raise AssertionError(f"package {index} differs from deterministic source")
    return {
        "section_offset": dep_start,
        "compressed_bytes": len(compressed),
        "uncompressed_bytes": len(inflated),
        "packages": len(packages),
        "format_version": document["format"],
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def create_fixtures(output: Path, gofmt: Path) -> dict[str, Any]:
    """Create benchmark fixtures and return paths plus independent manifests.

    ``gofmt`` must be an existing regular file supplied by the caller.  It is
    copied byte-for-byte; this function never executes the copied file.
    """

    output = output.resolve()
    gofmt = gofmt.resolve()
    if output.exists():
        raise FileExistsError(output)
    if not gofmt.is_file():
        raise FileNotFoundError(gofmt)
    output.mkdir(parents=True)

    small = output / "rust-small.elf"
    stress = output / "rust-stress.elf"
    sqlite_path = output / "settings.sqlite"
    copied_gofmt = output / "gofmt"
    small.write_bytes(_elf64_with_dep_v0(_auditable_document(SMALL_PACKAGE_COUNT)))
    stress.write_bytes(_elf64_with_dep_v0(_auditable_document(PACKAGE_COUNT)))
    _write_sqlite(sqlite_path)
    shutil.copy2(gofmt, copied_gofmt)

    source = str(gofmt)
    manifest = {
        "fixture_oracle_revision": FIXTURE_ORACLE_REVISION,
        "fixture_generator": {
            "path": str(Path(__file__).resolve()),
            "sha256": _sha256(Path(__file__).resolve()),
        },
        "rust_small": _manifest_entry(small),
        "rust_stress": _manifest_entry(stress),
        "sqlite": _manifest_entry(sqlite_path),
        "gofmt": _manifest_entry(copied_gofmt, source=source),
        "gofmt_source": _manifest_entry(gofmt, source=source),
        "gofmt_go_version_m": _go_version_oracle(copied_gofmt),
        "rust_small_independent": _independent_dep_check(small, SMALL_PACKAGE_COUNT),
        "rust_stress_independent": _independent_dep_check(stress, PACKAGE_COUNT),
    }
    return {
        "manifest": manifest,
        "paths": {
            "rust_small": small,
            "rust_stress": stress,
            "sqlite": sqlite_path,
            "gofmt": copied_gofmt,
        },
    }


def _artifact(evidence: dict[str, Any]) -> dict[str, Any]:
    result = evidence.get("normalized_result", evidence)
    artifact = result.get("artifact", {}) if isinstance(result, dict) else {}
    return artifact if isinstance(artifact, dict) else {}


def validate_evidence(task: str, evidence: dict[str, Any], fixtures: dict[str, Any]) -> None:
    """Assert identity and semantic facts in a completed provider response."""

    paths = fixtures["paths"]
    expected_key = {"inspect_rust_small": "rust_small", "inspect_rust_stress": "rust_stress", "inspect_go_binary": "gofmt"}.get(task)
    if expected_key is None:
        raise ValueError(f"unknown fixture task: {task}")
    expected_path = str(paths[expected_key])
    artifact = _artifact(evidence)
    if artifact.get("path") != expected_path:
        raise AssertionError("Evidence artifact path does not identify the fixture")
    expected_manifest = fixtures["manifest"][expected_key]
    if artifact.get("bytes") != expected_manifest["bytes"] or artifact.get("sha256") != expected_manifest["sha256"]:
        raise AssertionError("Evidence artifact digest or size differs from fixture")

    if task.startswith("inspect_rust"):
        metadata = evidence.get("normalized_result", evidence).get("auditable_metadata")
        expected_count = SMALL_PACKAGE_COUNT if task.endswith("small") else PACKAGE_COUNT
        if not isinstance(metadata, dict) or metadata.get("section_name") != ".dep-v0":
            raise AssertionError("Rust Evidence did not report .dep-v0 metadata")
        packages = metadata.get("packages")
        if not isinstance(packages, list) or len(packages) != expected_count:
            raise AssertionError("Rust Evidence package count differs from independent fixture")
        if metadata.get("file_offset") != DEP_OFFSET:
            raise AssertionError("Rust Evidence section offset differs from ELF source")
        if metadata.get("format_version") != 99:
            raise AssertionError("Rust Evidence did not preserve unknown format revision")
        if metadata.get("root_package_index") != 0:
            raise AssertionError("Rust Evidence root package differs from fixture")
        expected_edges = [
            {"from_index": index, "to_index": index - 1}
            for index in range(1, expected_count)
        ]
        if metadata.get("dependency_edges") != expected_edges:
            raise AssertionError("Rust Evidence dependency edge order differs from fixture")
        for index, package in enumerate(packages):
            expected = {
                "name": f"fixture-package-{index:05d}",
                "version": "1.0.0",
                "source": "registry+https://example.invalid/index",
                "kind": None,
                "dependencies": [] if index == 0 else [index - 1],
                "root": index == 0,
            }
            if package != expected:
                raise AssertionError(f"Rust Evidence package {index} differs from fixture")
    else:
        build_info = evidence.get("normalized_result", evidence).get("build_info")
        if not isinstance(build_info, dict) or not build_info.get("go_version"):
            raise AssertionError("Go Evidence omitted compiler version")
        oracle = fixtures["manifest"]["gofmt_go_version_m"]
        if build_info["go_version"] not in oracle["stdout"]:
            raise AssertionError("Go Evidence compiler version is absent from go version -m oracle")
        module = build_info.get("module")
        if not isinstance(module, dict):
            raise AssertionError("Go Evidence omitted module metadata")
        observed_path = module.get("path")
        observed_main = module.get("main")
        if observed_path != oracle["path"] and not (
            isinstance(observed_main, dict) and observed_main.get("path") == oracle["path"]
        ):
            raise AssertionError("Go Evidence module path differs from go version -m oracle")
        settings = module.get("settings")
        if not isinstance(settings, list):
            raise AssertionError("Go Evidence omitted build settings")
        for expected_setting in oracle["settings"]:
            if expected_setting not in settings:
                raise AssertionError(f"Go Evidence omitted setting {expected_setting['key']}")

