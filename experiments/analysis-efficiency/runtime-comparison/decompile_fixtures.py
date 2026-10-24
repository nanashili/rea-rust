#!/usr/bin/env python3
"""Prepare source-owned fixtures for the Java and Rust Ghidra comparison.

The target binaries are never executed here.  This module compiles only the
small C fixture, copies the already-installed Go binary, and records source and
tool identities together with independently useful symbol oracles.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
INVENTORY_SOURCE = ROOT / ".cache/runtime-benchmark-20261024-v2/typescript/tests/conformance/ghidra/inventory.c"
GO_SOURCE_ROOT = Path("/opt/homebrew/Cellar/go/1.26.5/libexec/src/cmd/gofmt")
DEFAULT_GOFMT = Path("/opt/homebrew/Cellar/go/1.26.5/libexec/bin/gofmt")
ORACLE_REVISION = "decompile-fixtures-v1"

SMALL_SYMBOLS = (
    "rea_ghidra_inventory_entry",
    "rea_ghidra_inventory_leaf",
    "rea_ghidra_inventory_branch",
)
SMALL_GLOBAL_SYMBOL = "rea_ghidra_inventory_global"
SMALL_CALL_EXPECTATIONS = {
    "rea_ghidra_inventory_entry": (
        "rea_ghidra_inventory_branch",
        "rea_ghidra_inventory_indirect",
    ),
    "rea_ghidra_inventory_branch": ("rea_ghidra_inventory_leaf",),
}
GO_SYMBOLS = ("main", "gofmtMain", "processFile")
GO_SOURCE_FILES = ("gofmt.go", "internal.go")
SMALL_SOURCE_FACTS = {
    "rea_ghidra_inventory_entry": {
        "calls": (
            "rea_ghidra_inventory_branch",
            "rea_ghidra_inventory_indirect",
            "rea_ghidra_inventory_dense_switch",
        ),
        "literals": ("35", "100"),
    },
    "rea_ghidra_inventory_leaf": {
        "calls": ("puts",),
        "literals": ("REA_GHIDRA_LEAF_VALUE",),
        "expressions": ("value + rea_ghidra_inventory_global",),
    },
    "rea_ghidra_inventory_branch": {
        "calls": ("rea_ghidra_inventory_leaf",),
        "literals": ("10",),
        "expressions": ("value > 10", "-value"),
    },
}
GO_SOURCE_FACTS = {
    "main": {"calls": ("gofmtMain",), "literals": ("2 << 20",)},
    "gofmtMain": {"calls": ("processFile", "initParserMode", "initRewrite")},
    "processFile": {
        "calls": ("readFile", "format", "writeFile"),
        "expressions": ("bytes.Equal(src, res)",),
    },
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _file_record(path: Path, *, source: str | None = None) -> dict[str, Any]:
    record: dict[str, Any] = {
        "path": path.name,
        "bytes": path.stat().st_size,
        "sha256": _sha256(path),
    }
    if source is not None:
        record["source"] = source
    return record


def _run_capture(command: list[str], *, cwd: Path | None = None) -> dict[str, Any]:
    result = subprocess.run(
        command,
        cwd=cwd,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={**os.environ, "LC_ALL": "C"},
    )
    return {
        "command": command,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def _source_record(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    return {
        "path": str(path),
        "bytes": path.stat().st_size,
        "sha256": _sha256(path),
        "lines": text.count("\n") + (0 if text.endswith("\n") else 1),
    }


def _nm_symbols(
    binary: Path,
    names: tuple[str, ...],
    *,
    command: list[str] | None = None,
) -> dict[str, dict[str, str]]:
    """Read symbols without loading or executing the target binary."""

    output = _run_capture(command or ["nm", "-g", str(binary)])
    found: dict[str, dict[str, str]] = {}
    wanted = set(names)
    for line in output["stdout"].splitlines():
        fields = line.split()
        if len(fields) < 3:
            continue
        address, kind, name = fields[-3:]
        canonical = name[1:] if name.startswith("_") else name
        short_name = canonical.rsplit(".", 1)[-1]
        if canonical in wanted:
            matched_name = canonical
        elif short_name in wanted:
            # Go binaries contain both runtime.main and main.main.  The
            # source oracle is the package's main, so do not accept runtime.
            if short_name == "main" and canonical != "main.main":
                continue
            matched_name = short_name
        else:
            continue
        if matched_name in wanted:
            found[matched_name] = {
                "address": address.lower().removeprefix("0x"),
                "kind": kind,
                "raw_name": name,
            }
    missing = sorted(wanted - found.keys())
    if missing:
        raise RuntimeError(f"nm did not expose expected fixture symbols: {missing}")
    return found


def _source_facts(path: Path, functions: tuple[str, ...]) -> dict[str, dict[str, Any]]:
    text = path.read_text(encoding="utf-8")
    facts: dict[str, dict[str, Any]] = {}
    for function in functions:
        match = re.search(rf"\b(?:static\s+)?[^\n;{{]+\b{re.escape(function)}\s*\([^)]*\)\s*{{", text)
        if match is None:
            raise RuntimeError(f"source function is absent: {function}")
        facts[function] = {
            "source_file": str(path),
            "line": text.count("\n", 0, match.start()) + 1,
        }
    return facts


def _go_function_facts(source_root: Path) -> dict[str, dict[str, Any]]:
    files = {name: (source_root / name).read_text(encoding="utf-8") for name in GO_SOURCE_FILES}
    facts: dict[str, dict[str, Any]] = {}
    for function in GO_SYMBOLS:
        matches = [
            (name, text)
            for name, text in files.items()
            if re.search(rf"\bfunc\s+{re.escape(function)}\s*\(", text)
        ]
        if not matches:
            raise RuntimeError(f"Go source function is absent: {function}")
        name, text = matches[0]
        facts[function] = {
            "source_file": str(source_root / name),
            "line": next(
                index
                for index, line in enumerate(text.splitlines(), 1)
                if re.search(rf"\bfunc\s+{re.escape(function)}\s*\(", line)
            ),
        }
    return facts


def _copy_source(source: Path, destination: Path) -> dict[str, Any]:
    if not source.is_file():
        raise FileNotFoundError(source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    return _file_record(destination, source=str(source))


def create_decompile_fixtures(
    output: Path,
    *,
    gofmt: Path = DEFAULT_GOFMT,
    go_source_root: Path = GO_SOURCE_ROOT,
    inventory_source: Path = INVENTORY_SOURCE,
) -> dict[str, Any]:
    """Create fixtures and return a manifest with source-level expectations.

    The caller should invoke this after any worker build has finished.  The
    function itself does not inspect worker state and does not execute either
    target fixture.
    """

    output = output.resolve()
    gofmt = gofmt.resolve()
    go_source_root = go_source_root.resolve()
    inventory_source = inventory_source.resolve()
    if output.exists():
        raise FileExistsError(output)
    if not gofmt.is_file() or not gofmt.stat().st_mode & 0o111:
        raise FileNotFoundError(f"regular executable gofmt required: {gofmt}")
    if not inventory_source.is_file():
        raise FileNotFoundError(inventory_source)
    for name in GO_SOURCE_FILES:
        if not (go_source_root / name).is_file():
            raise FileNotFoundError(go_source_root / name)

    output.mkdir(parents=True)
    small_source = output / "inventory.c"
    small_binary = output / "inventory-debug"
    _copy_source(inventory_source, small_source)
    compiler = shutil.which("cc")
    if compiler is None:
        raise RuntimeError("host C compiler 'cc' is required")
    compile_command = [compiler, "-O0", "-g", "-fno-inline", str(small_source), "-o", str(small_binary)]
    compiler_version = _run_capture([compiler, "--version"])
    _run_capture(compile_command)

    go_binary = output / "gofmt"
    shutil.copyfile(gofmt, go_binary)
    go_binary.chmod(gofmt.stat().st_mode & 0o777)
    go = shutil.which("go") or "go"
    go_version = _run_capture([go, "version", "-m", str(go_binary)])

    source_oracles = output / "source-oracle"
    go_sources = [_copy_source(go_source_root / name, source_oracles / name) for name in GO_SOURCE_FILES]
    manifest = {
        "oracle_revision": ORACLE_REVISION,
        "targets": {
            "small": {
                "binary": _file_record(small_binary),
                "source": _file_record(small_source, source=str(inventory_source)),
                "compile": {"command": compile_command, "compiler": compiler_version},
                "symbols": _nm_symbols(small_binary, SMALL_SYMBOLS),
                "global_symbol": _nm_symbols(small_binary, (SMALL_GLOBAL_SYMBOL,))[SMALL_GLOBAL_SYMBOL],
                "expected_calls": SMALL_CALL_EXPECTATIONS,
                "source_facts": {
                    **_source_facts(small_source, SMALL_SYMBOLS),
                    "expectations": SMALL_SOURCE_FACTS,
                },
            },
            "gofmt": {
                "binary": _file_record(go_binary, source=str(gofmt)),
                "go_version_oracle": go_version,
                "source_files": go_sources,
                "symbols": _nm_symbols(go_binary, GO_SYMBOLS, command=[go, "tool", "nm", str(go_binary)]),
                "source_facts": {
                    **_go_function_facts(go_source_root),
                    "expectations": GO_SOURCE_FACTS,
                },
            },
        },
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest


def _records(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        for key in ("functions", "procedures", "results"):
            if isinstance(value.get(key), list):
                return [item for item in value[key] if isinstance(item, dict)]
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    return []


def _canonical_symbol_name(name: str) -> str:
    return name.lstrip("_")


def _pseudocode_text(record: dict[str, Any]) -> str:
    value = record.get("pseudocode")
    if not isinstance(value, str) or not value.strip():
        raise AssertionError(f"missing pseudocode for {record.get('name', '<unknown>')}")
    return value


def _has_number(text: str, decimal: int, hexadecimal: str) -> bool:
    return bool(
        re.search(rf"(?<![A-Za-z0-9]){decimal}(?![A-Za-z0-9])", text)
        or re.search(rf"0x{hexadecimal}(?![A-Za-z0-9])", text, re.IGNORECASE)
    )


def _has_call(text: str, symbol: str) -> bool:
    return bool(
        re.search(
            rf"(?<![A-Za-z0-9_])(?:_?main[_\.])?_?{re.escape(symbol)}\s*\(",
            text,
        )
    )


def validate_pseudocode_records(
    records: Any,
    manifest: dict[str, Any],
    target: str,
) -> dict[str, Any]:
    """Check source-known facts without asserting text identity across engines.

    The check intentionally accepts provider presentation differences.  For
    example, Java Ghidra may render a string literal while the Rust worker may
    render the corresponding data address.  It still requires the selected
    functions and their meaningful source-level calls/control facts.
    """

    rows = _records(records)
    expected = manifest["targets"][target]
    expected_names = set(expected["source_facts"]["expectations"])
    by_name = {
        _canonical_symbol_name(str(row.get("name", ""))): row
        for row in rows
        if isinstance(row, dict) and row.get("name")
    }
    missing = sorted(expected_names - by_name.keys())
    if missing:
        raise AssertionError(f"missing pseudocode records for {target}: {missing}")

    checks: dict[str, dict[str, Any]] = {}
    for name, row in by_name.items():
        text = _pseudocode_text(row)
        checks[name] = {"status": row.get("status", "unknown"), "facts": {}}
        if row.get("status") not in (None, "success"):
            raise AssertionError(f"pseudocode failed for {name}: {row.get('status')}")

        if target == "small":
            if name == "rea_ghidra_inventory_entry":
                required = (
                    "rea_ghidra_inventory_branch",
                    "rea_ghidra_inventory_indirect",
                    "rea_ghidra_inventory_dense_switch",
                )
                for callee in required:
                    if not _has_call(text, callee):
                        raise AssertionError(f"entry is missing direct call {callee}")
                for decimal, hexadecimal in ((35, "23"), (100, "64")):
                    if not _has_number(text, decimal, hexadecimal):
                        raise AssertionError(f"entry is missing source constant {decimal}")
                checks[name]["facts"] = {"calls": list(required), "constants": [35, 100]}
            elif name == "rea_ghidra_inventory_branch":
                if not _has_call(text, "rea_ghidra_inventory_leaf") or "-param_1" not in text:
                    raise AssertionError("branch is missing leaf call or negative path")
                if not ("param_1 < 10" in text or "param_1 + -10" in text):
                    raise AssertionError("branch condition was not preserved")
                checks[name]["facts"] = {"calls": ["rea_ghidra_inventory_leaf"], "negative_path": True}
            elif name == "rea_ghidra_inventory_leaf":
                if not _has_call(text, "puts"):
                    raise AssertionError("leaf is missing puts call")
                if not re.search(r"return\b[^\n]*\+", text):
                    raise AssertionError("leaf is missing value-plus-global return")
                address = expected["global_symbol"]["address"].lstrip("0") or "0"
                has_global_address = address.lower() in text.lower().replace("0x", "")
                has_global_symbol = _canonical_symbol_name(SMALL_GLOBAL_SYMBOL) in text
                if not (has_global_address or has_global_symbol):
                    raise AssertionError("leaf addition has no source global symbol or recorded global address")
                checks[name]["facts"] = {
                    "calls": ["puts"],
                    "addition": True,
                    "global_display": "address" if has_global_address else "symbol",
                    "global_address_seen": has_global_address,
                    "global_symbol_seen": has_global_symbol,
                    "leaf_marker_display": (
                        "string_literal"
                        if "REA_GHIDRA_LEAF_VALUE" in text
                        else "raw_address_or_other"
                    ),
                }
        elif target == "gofmt":
            facts = expected["source_facts"]["expectations"].get(name, {})
            observed_calls = [call for call in facts.get("calls", ()) if _has_call(text, call)]
            checks[name]["facts"] = {
                "observed_calls": observed_calls,
                "unverified_source_calls": [
                    call for call in facts.get("calls", ()) if call not in observed_calls
                ],
                "source_backed": True,
                "limitation": "Go compiler/linker inlining and provider presentation can hide source calls",
            }

    return {"target": target, "checks": checks}


def validate_decompile_evidence(evidence: Any, manifest: dict[str, Any], target: str) -> None:
    """Validate required function names and source-backed call facts.

    ``evidence`` may be one normalized function result or a result containing
    ``functions``/``procedures``.  Pseudocode text is intentionally not
    compared between Java and Rust; only source-known facts are checked.
    """

    target_manifest = manifest["targets"][target]
    records = _records(evidence)
    if not records:
        raise AssertionError("decompile evidence has no function result")
    names = {item.get("name") for item in records if isinstance(item, dict)}
    expected = set(target_manifest.get("symbols", {}))
    if len(records) == 1 and records[0].get("name"):
        expected = {records[0]["name"]}
    missing = sorted(expected - names)
    if missing:
        raise AssertionError(f"missing expected functions for {target}: {missing}")
    expectations = target_manifest["source_facts"]["expectations"]
    for record in records:
        name = record.get("name") or record.get("function") or record.get("procedure")
        if name not in expectations:
            continue
        observed_calls = record.get("calls", record.get("callees"))
        if isinstance(observed_calls, list):
            observed_names = {
                item.get("name") if isinstance(item, dict) else item
                for item in observed_calls
            }
            missing_calls = sorted(set(expectations[name].get("calls", ())) - observed_names)
            if missing_calls:
                raise AssertionError(f"source-known calls missing from {name}: {missing_calls}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--gofmt", type=Path, default=DEFAULT_GOFMT)
    args = parser.parse_args()
    print(json.dumps(create_decompile_fixtures(args.output, gofmt=args.gofmt), indent=2, sort_keys=True))
