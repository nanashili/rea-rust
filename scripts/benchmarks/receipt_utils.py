"""Small, shared helpers for compact benchmark receipt interpretation."""

from __future__ import annotations

import json
from typing import Any


MAX_ERROR_REASON = 240


def compact_text(value: Any) -> str:
    if isinstance(value, str):
        text = value
    else:
        try:
            text = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
        except (TypeError, ValueError):
            text = str(value)
    return " ".join(text.split())[:MAX_ERROR_REASON]


def harness_error_code(reason: Any) -> str | None:
    text = compact_text(reason).lower()
    if "stdout queue limit" in text or "stdout-queue-limit" in text:
        return "harness_stdout_queue_limit"
    if "memoryerror" in text or "family-rss-limit" in text or "process-family rss limit" in text:
        return "harness_rss_limit"
    if "timeouterror" in text or "call-timeout" in text or "mcp call timed out" in text:
        return "harness_call_timeout"
    return None


def error_summary(value: Any) -> tuple[str | None, str | None]:
    """Return a protocol code and bounded reason without treating MIME type as a code."""
    if isinstance(value, dict):
        content = value.get("content")
        if isinstance(content, list):
            for item in content:
                if not isinstance(item, dict) or not isinstance(item.get("text"), str):
                    continue
                text = item["text"]
                try:
                    parsed = json.loads(text)
                except (TypeError, ValueError):
                    code = harness_error_code(text)
                    return code, compact_text(text)
                found = error_summary(parsed)
                if found != (None, None):
                    return found

        code_value = value.get("code") or value.get("errorCode")
        reason_value = value.get("message") or value.get("reason") or value.get("error")
        if reason_value is not None:
            if isinstance(reason_value, (dict, list)):
                nested_code, nested_reason = error_summary(reason_value)
                if nested_code is not None or nested_reason is not None:
                    return nested_code, nested_reason

            harness_code = harness_error_code(reason_value)
            return (harness_code or (str(code_value) if code_value is not None else None), compact_text(reason_value))
        if code_value is not None:
            return str(code_value), None

        for key, child in value.items():
            if key == "type":
                continue
            found = error_summary(child)
            if found != (None, None):
                return found
    elif isinstance(value, list):
        for child in value:
            found = error_summary(child)
            if found != (None, None):
                return found
    elif value is not None:
        code = harness_error_code(value)
        return code, compact_text(value)
    return None, None
