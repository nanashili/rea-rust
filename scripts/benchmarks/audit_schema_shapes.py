#!/usr/bin/env python3
"""Check successful MCP object payloads against compatible schema constraints.

This audit uses Node's jsonschema package after removing schema identifiers and
dialect declarations. It is not declared-dialect conformance validation, and it
does not establish whether the returned facts are correct.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

NODE_VALIDATOR = r'''
const fs = require("fs");
const Validator = require("jsonschema").Validator;
const input = JSON.parse(fs.readFileSync(0, "utf8"));
const validator = new Validator();
const output = {
  validator_version: require("jsonschema/package.json").version,
  valid: [],
  invalid: [],
  validator_errors: [],
};
for (const item of input.items) {
  let schema = input.schemas[item.tool];
  if (!schema) {
    output.validator_errors.push({file:item.file, tool:item.tool, error:"missing current catalog output schema"});
    continue;
  }
  let checked;
  try {
    checked = validator.validate(item.payload, schema);
  } catch (error) {
    output.validator_errors.push({file:item.file, tool:item.tool, error:String(error)});
    continue;
  }
  if (checked.valid) {
    output.valid.push({file:item.file, tool:item.tool});
    continue;
  }
  output.invalid.push({
    file: item.file,
    tool: item.tool,
    errors: checked.errors.map(error => ({
      property: error.property,
      name: error.name,
      message: error.message,
      argument: error.argument,
    })),
  });
}
process.stdout.write(JSON.stringify(output));
'''


def arguments_parser() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", required=True, type=Path)
    parser.add_argument("--catalog", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def remove_identifiers(value):
    if isinstance(value, dict):
        return {
            key: remove_identifiers(child)
            for key, child in value.items()
            if key not in {"$id", "$schema"}
        }
    if isinstance(value, list):
        return [remove_identifiers(child) for child in value]
    return value


def load_catalog(path: Path) -> tuple[dict, str]:
    raw = path.read_bytes()
    catalog = json.loads(raw)
    schemas = {
        entry["advertised"]["name"]: remove_identifiers(entry["advertised"]["outputSchema"])
        for entry in catalog["tools"]
    }
    digest = hashlib.sha256(raw).hexdigest()
    return schemas, digest


def payload_from_receipt(receipt: dict) -> tuple[dict | None, str | None]:
    response = receipt.get("response", {}).get("result", {})
    structured = response.get("structuredContent")
    if isinstance(structured, dict):
        return structured, None

    for content in response.get("content", []):
        if not isinstance(content, dict) or content.get("type") != "text":
            continue
        try:
            payload = json.loads(content["text"])
        except (TypeError, json.JSONDecodeError) as error:
            return None, f"content text is not JSON: {error}"
        if isinstance(payload, dict):
            return payload, None
    return None, "no structuredContent or JSON object in content"


def collect_receipts(runs: Path) -> tuple[list[dict], dict]:
    items: list[dict] = []
    counts = {
        "receipt_count": 0,
        "successful_receipts": 0,
        "successful_structured_payloads": 0,
        "skipped_unsuccessful": 0,
        "skipped_unstructured": 0,
        "malformed_successful": 0,
    }
    skipped: list[dict] = []
    for path in sorted(runs.glob("*/call-*.json")):
        counts["receipt_count"] += 1
        receipt = json.loads(path.read_text())
        if receipt.get("status") != "success":
            counts["skipped_unsuccessful"] += 1
            continue
        counts["successful_receipts"] += 1
        params = receipt.get("request", {}).get("params", {})
        tool = params.get("name")
        payload, issue = payload_from_receipt(receipt)
        if payload is None:
            counts["skipped_unstructured"] += 1
            if issue and "not JSON" in issue:
                counts["malformed_successful"] += 1
            skipped.append({"file": str(path), "tool": tool, "reason": issue})
            continue
        counts["successful_structured_payloads"] += 1
        items.append({"file": str(path), "tool": tool, "payload": payload})
    return items, {"counts": counts, "skipped": skipped}


def validate(items: list[dict], schemas: dict) -> dict:
    request = json.dumps({"schemas": schemas, "items": items})
    try:
        completed = subprocess.run(
            ["node", "-e", NODE_VALIDATOR],
            input=request,
            text=True,
            capture_output=True,
            check=False,
        )
    except OSError as error:
        raise RuntimeError(f"could not run node validator: {error}") from error
    if completed.returncode:
        raise RuntimeError(completed.stderr.strip() or "node validator failed")
    return json.loads(completed.stdout)


def main() -> int:
    args = arguments_parser()
    schemas, catalog_sha256 = load_catalog(args.catalog)
    items, collection = collect_receipts(args.runs)
    try:
        validation = validate(items, schemas)
    except RuntimeError as error:
        print(f"rea-schema-audit: {error}", file=sys.stderr)
        print("Install jsonschema for Node or set NODE_PATH to a directory containing it.", file=sys.stderr)
        return 2
    report = {
        "validator": {
            "name": "jsonschema",
            "version": validation["validator_version"],
            "mode": "compatible_shape_constraints",
            "schema_transform": "recursively remove $id and $schema",
            "limitations": [
                "Does not validate full conformance to the declared schema dialect.",
                "Does not establish factual correctness or semantic completeness.",
                "Failed calls and successful calls without object payloads are skipped.",
            ],
        },
        "schema_source": {"path": str(args.catalog), "sha256": catalog_sha256},
        "runs": str(args.runs),
        "collection": collection,
        "validation": {
            "valid_count": len(validation["valid"]),
            "invalid_count": len(validation["invalid"]),
            "validator_error_count": len(validation["validator_errors"]),
            "invalid": validation["invalid"],
            "validator_errors": validation["validator_errors"],
        },
    }
    serialized = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(serialized)
    print(serialized, end="")
    return 1 if validation["invalid"] or validation["validator_errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
