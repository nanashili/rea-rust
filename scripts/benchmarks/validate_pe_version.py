#!/usr/bin/env python3
"""Validate a PE RT_VERSION payload independently of REA's parser.

The script reads the payload from the target file, checks the receipt's byte
range and digest, then parses VS_VERSION_INFO with its own bounded parser.  A
REA result may be supplied for comparison, but provider output is evidence
about that run and is never treated as proof of the independent parse.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from receipt_utils import compact_text


DEFAULT_OFFSET = 2_585_688
DEFAULT_BYTES = 644
DEFAULT_PAYLOAD_SHA256 = "e40cab087151f2e6df68e8ee6915bc267354d4e9d067ce6aba4e8cce0eebeb3b"


class VersionParseError(ValueError):
    """A malformed or unsupported bounded VERSIONINFO block."""


@dataclass
class VersionBlock:
    offset: int
    length: int
    value_length: int
    value_type: int
    key: str
    value: bytes
    children: list["VersionBlock"] = field(default_factory=list)


def align4(value: int, end: int, label: str) -> int:
    if value == end:
        return value
    aligned = (value + 3) & ~3
    if aligned > end:
        raise VersionParseError(f"{label} alignment exceeds block extent")
    return aligned


def read_key(payload: bytes, start: int, end: int) -> tuple[str, int]:
    cursor = start
    units: list[int] = []
    while cursor + 2 <= end:
        unit = struct.unpack_from("<H", payload, cursor)[0]
        cursor += 2
        if unit == 0:
            try:
                key_bytes = b"".join(struct.pack("<H", item) for item in units)
                return key_bytes.decode("utf-16le"), cursor
            except UnicodeDecodeError as exc:
                raise VersionParseError("VERSIONINFO key is not valid UTF-16LE") from exc
        units.append(unit)
    raise VersionParseError("VERSIONINFO key is unterminated")


def parse_block(payload: bytes, start: int, parent_end: int) -> VersionBlock:
    if start < 0 or start + 6 > parent_end:
        raise VersionParseError("VERSIONINFO block header is truncated")

    length, value_length, value_type = struct.unpack_from("<HHH", payload, start)
    if length < 6 or start + length > parent_end:
        raise VersionParseError("VERSIONINFO block length exceeds parent extent")
    if value_type not in (0, 1):
        raise VersionParseError("VERSIONINFO value type is unsupported")
    block_end = start + length

    key, cursor = read_key(payload, start + 6, block_end)
    value_start = align4(cursor, block_end, "VERSIONINFO value")
    value_bytes = value_length * 2 if value_type == 1 else value_length
    value_end = value_start + value_bytes
    if value_end > block_end:
        raise VersionParseError("VERSIONINFO value exceeds block extent")

    block = VersionBlock(
        offset=start,
        length=length,
        value_length=value_length,
        value_type=value_type,
        key=key,
        value=payload[value_start:value_end],
    )

    child = align4(value_end, block_end, "VERSIONINFO child")
    while child < block_end:
        if all(byte == 0 for byte in payload[child:block_end]):
            break
        if child + 2 > block_end or struct.unpack_from("<H", payload, child)[0] == 0:
            raise VersionParseError("VERSIONINFO has non-zero trailing padding")
        child_block = parse_block(payload, child, block_end)
        block.children.append(child_block)
        child = align4(child + child_block.length, block_end, "VERSIONINFO sibling")

    return block


def utf16_value(block: VersionBlock) -> str:
    if block.value_type != 1:
        raise VersionParseError(f"string value {block.key!r} has non-string type")
    try:
        return block.value.decode("utf-16le").rstrip("\x00")
    except UnicodeDecodeError as exc:
        raise VersionParseError(f"string value {block.key!r} is not valid UTF-16LE") from exc


def flatten(block: VersionBlock) -> list[VersionBlock]:
    return [block, *[item for child in block.children for item in flatten(child)]]


def fixed_file_info(root: VersionBlock) -> dict[str, Any]:
    if root.value_length < 52 or len(root.value) < 52:
        raise VersionParseError("VS_FIXEDFILEINFO is truncated")
    signature, structure_version = struct.unpack_from("<II", root.value)
    if signature != 0xFEEF04BD:
        raise VersionParseError("VS_FIXEDFILEINFO signature is invalid")
    file_ms, file_ls, product_ms, product_ls = struct.unpack_from("<IIII", root.value, 8)

    def version(ms: int, ls: int) -> str:
        return f"{ms >> 16}.{ms & 0xffff}.{ls >> 16}.{ls & 0xffff}"

    return {
        "signature": f"0x{signature:08x}",
        "structure_version": structure_version,
        "file_version": version(file_ms, file_ls),
        "product_version": version(product_ms, product_ls),
        "file_version_ms": file_ms,
        "file_version_ls": file_ls,
        "product_version_ms": product_ms,
        "product_version_ls": product_ls,
    }


def independent_version(payload: bytes) -> dict[str, Any]:
    root = parse_block(payload, 0, len(payload))
    if root.key != "VS_VERSION_INFO":
        raise VersionParseError(f"unexpected root key {root.key!r}")
    if root.value_type != 0 or root.value_length != 52:
        raise VersionParseError("VS_VERSION_INFO fixed value has an invalid type or length")
    if root.length != len(payload):
        raise VersionParseError("VS_VERSION_INFO does not cover the complete payload")

    strings: dict[str, list[str]] = {}
    for block in flatten(root):
        if block.children:
            continue
        if block.value_type == 1:
            strings.setdefault(block.key, []).append(utf16_value(block))

    return {
        "root": {"key": root.key, "length": root.length, "value_length": root.value_length},
        "fixed_file_info": fixed_file_info(root),
        "strings": strings,
        "blocks": len(flatten(root)),
    }


def sha256_file(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            size += len(chunk)
            digest.update(chunk)
    return size, digest.hexdigest()


def find_provider_values(
    value: Any,
    found: dict[str, list[str]] | None = None,
) -> dict[str, list[str]]:
    found = {} if found is None else found
    if isinstance(value, dict):
        for key, item in value.items():
            if key.lower() in {
                "fileversion",
                "productversion",
                "file_version",
                "product_version",
            }:
                if isinstance(item, str):
                    found.setdefault(key, []).append(item)
            find_provider_values(item, found)
    elif isinstance(value, list):
        for item in value:
            find_provider_values(item, found)
    return found


def find_limitations(value: Any, found: list[str] | None = None) -> list[str]:
    found = [] if found is None else found
    if isinstance(value, dict):
        limitations = value.get("limitations")
        if isinstance(limitations, list):
            found.extend(item for item in limitations if isinstance(item, str))
        for item in value.values():
            find_limitations(item, found)
    elif isinstance(value, list):
        for item in value:
            find_limitations(item, found)
    return list(dict.fromkeys(found))


def provider_documents(path: Path) -> list[Any]:
    """Extract structured JSON from a direct result or MCP call envelope."""
    value = json.loads(path.read_text())
    documents: list[Any] = []
    if isinstance(value, dict):
        response = value.get("response")
        result = response.get("result") if isinstance(response, dict) else None
        structured = result.get("structuredContent") if isinstance(result, dict) else None
        if structured is not None:
            documents.append(structured)
        content = result.get("content") if isinstance(result, dict) else None
        for item in content if isinstance(content, list) else []:
            if not isinstance(item, dict) or not isinstance(item.get("text"), str):
                continue
            try:
                documents.append(json.loads(item["text"]))
            except json.JSONDecodeError:
                continue
    if not documents:
        documents.append(value)
    return documents


def compare_provider(paths: list[Path], oracle: dict[str, Any]) -> dict[str, Any]:
    if not paths:
        return {"status": "not_requested", "authoritative": False}
    results: list[dict[str, Any]] = []
    expected = {
        "FileVersion": oracle["fixed_file_info"]["file_version"],
        "ProductVersion": oracle["fixed_file_info"]["product_version"],
    }
    for path in paths:
        try:
            documents = provider_documents(path)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            results.append(
                {
                    "path": str(path),
                    "status": "unreadable",
                    "error": type(exc).__name__,
                    "detail": compact_text(str(exc)),
                }
            )
            continue
        document_values: dict[str, list[str]] = {}
        document_limitations: list[str] = []
        for document in documents:
            for key, items in find_provider_values(document).items():
                document_values.setdefault(key, []).extend(items)
            document_limitations.extend(find_limitations(document))
        normalized_values: dict[str, list[str]] = {}
        for key, items in document_values.items():
            normalized_key = key.replace("_", "").lower()
            normalized_values.setdefault(normalized_key, []).extend(items)
        matches = {
            key: bool(normalized_values.get(key.lower()))
            and all(item == expected[key] for item in normalized_values[key.lower()])
            for key in expected
        }
        expected_keys = {key.lower() for key in expected}
        normalized_distinct = {
            key: sorted(set(normalized_values.get(key, [])))
            for key in expected_keys
            if key in normalized_values
        }
        if not document_values:
            status = "not_present"
        elif any(len(items) != 1 for items in normalized_distinct.values()):
            status = "conflicting_values"
        elif not all(matches.values()):
            status = "mismatch"
        else:
            status = "values_present"
        results.append(
            {
                "path": str(path),
                "status": status,
                "values": document_values,
                "limitations": list(dict.fromkeys(document_limitations)),
                "matches": matches,
            }
        )

    statuses = [item["status"] for item in results]
    if statuses and all(status == "values_present" for status in statuses):
        status = "values_present"
    elif "unreadable" in statuses:
        status = "unreadable"
    elif "conflicting_values" in statuses:
        status = "conflicting_values"
    elif "mismatch" in statuses:
        status = "mismatch"
    else:
        status = "not_present"
    observed: dict[str, list[str]] = {}
    limitations: list[str] = []
    for item in results:
        limitations.extend(item.get("limitations", []))
        for key, values in item.get("values", {}).items():
            observed.setdefault(key, []).extend(values)
    aggregate_matches = {
        key: bool(statuses)
        and all(item.get("status") == "values_present" for item in results)
        for key in expected
    }
    return {
        "status": status,
        "authoritative": False,
        "result_paths": [str(path) for path in paths],
        "results": results,
        "observed": observed,
        "limitations": list(dict.fromkeys(limitations)),
        "expected": expected,
        "matches": aggregate_matches,
        "provider_limitations_remain": True,
    }


def resolve_result_paths(result: Path | None, workdir: Path | None) -> list[Path]:
    if result is not None and workdir is not None:
        raise ValueError("--rea-result and --workdir are mutually exclusive")
    if result is not None:
        return [result]
    if workdir is None:
        return []
    if not workdir.is_absolute() or not workdir.is_dir():
        raise ValueError("--workdir must name an existing absolute directory")

    candidates = []
    json_paths = sorted(workdir.rglob("call-*.json"))
    if not json_paths:
        json_paths = sorted(workdir.rglob("*.json"))
    for path in json_paths:
        try:
            text = path.read_text()
            value = json.loads(text)
        except json.JSONDecodeError:
            if "inspect_pe_resources" in text:
                candidates.append(path)
            continue
        except (OSError, UnicodeDecodeError):
            continue
        request = value.get("request") if isinstance(value, dict) else None
        params = request.get("params") if isinstance(request, dict) else None
        operation = params.get("name") if isinstance(params, dict) else None
        direct_operation = value.get("operation") if isinstance(value, dict) else None
        if operation == "inspect_pe_resources" or direct_operation == "inspect_pe_resources":
            candidates.append(path)
    if not candidates:
        raise ValueError("--workdir contains no inspect_pe_resources JSON results")
    return candidates


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--target", required=True, type=Path, help="absolute path to the PE file")
    result.add_argument("--payload-offset", type=int, default=DEFAULT_OFFSET)
    result.add_argument("--payload-bytes", type=int, default=DEFAULT_BYTES)
    result.add_argument("--payload-sha256", default=DEFAULT_PAYLOAD_SHA256)
    result.add_argument("--rea-result", "--result", dest="rea_result", type=Path)
    result.add_argument(
        "--workdir",
        type=Path,
        help="absolute directory containing inspect_pe_resources JSON results",
    )
    return result


def main() -> int:
    args = parser().parse_args()
    if not args.target.is_absolute():
        print(
            json.dumps(
                {"status": "error", "error": "target_must_be_absolute"},
                indent=2,
            )
        )
        return 2
    if args.payload_offset < 0 or args.payload_bytes < 0:
        print(
            json.dumps(
                {"status": "error", "error": "payload_range_invalid"},
                indent=2,
            )
        )
        return 2
    try:
        provider_results = resolve_result_paths(args.rea_result, args.workdir)
    except ValueError as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, indent=2))
        return 2

    try:
        file_bytes, file_sha256 = sha256_file(args.target)
        with args.target.open("rb") as stream:
            stream.seek(args.payload_offset)
            payload = stream.read(args.payload_bytes)
    except OSError as exc:
        print(
            json.dumps(
                {
                    "status": "error",
                    "error": "target_unavailable",
                    "detail": str(exc),
                },
                indent=2,
            )
        )
        return 2

    result: dict[str, Any] = {
        "status": "error",
        "oracle": "independent-pe-versioninfo",
        "target": {"path": str(args.target), "bytes": file_bytes, "sha256": file_sha256},
        "payload": {
            "offset": args.payload_offset,
            "bytes": len(payload),
            "expected_bytes": args.payload_bytes,
            "sha256": hashlib.sha256(payload).hexdigest(),
            "expected_sha256": args.payload_sha256,
        },
    }
    if len(payload) != args.payload_bytes or args.payload_offset + len(payload) > file_bytes:
        result["error"] = "payload_range_out_of_bounds_or_truncated"
        print(json.dumps(result, indent=2, sort_keys=True))
        return 1
    if result["payload"]["sha256"] != args.payload_sha256:
        result["error"] = "payload_sha256_mismatch"
        print(json.dumps(result, indent=2, sort_keys=True))
        return 1

    try:
        oracle = independent_version(payload)
    except VersionParseError as exc:
        result["error"] = "malformed_version_info"
        result["detail"] = str(exc)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 1

    result["status"] = "success"
    result["version_info"] = oracle
    result["provider_comparison"] = compare_provider(provider_results, oracle)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
