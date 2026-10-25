"""Stage the authored REA skill for a standalone release."""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path


SKILL_NAME = "reverse-engineer-anything"
MANAGED_FILES = (
    "SKILL.md",
    "references/connection-and-recovery.md",
    "references/native-and-artifacts.md",
    "references/javascript-applications.md",
    "references/android-applications.md",
    "references/runtime-observation.md",
    "references/evidence-workflows.md",
)
CATALOG_PATH = Path("crates/interfaces/rea-mcp/contracts/catalog/mcp-tools.json")
VERSION_LINE = re.compile(r'^  version: "[^"\r\n]+"$', re.MULTILINE)
TOOL_COUNT_LINE = re.compile(r"^  tool_count: \d+$", re.MULTILINE)


def stage_skill(repository: Path, destination: Path) -> Path:
    """Stage the release skill and return its staged directory.

    ``repository`` must contain the authored ``.agents`` skill and the frozen
    MCP catalog. The staged ``SKILL.md`` receives the catalog tool count,
    matching the generated skill consumed by ``rea setup``. All other managed
    files are copied as normalized UTF-8 text.
    """

    source = repository / ".agents/skills" / SKILL_NAME
    staged = destination / "skills" / SKILL_NAME
    files = _read_authored_files(source)
    tool_count = _read_tool_count(repository / CATALOG_PATH)

    rendered_skill = _render_skill(files["SKILL.md"], tool_count)
    if staged.is_symlink():
        raise ValueError(f"staged skill path must not be a symbolic link: {staged}")
    if staged.exists():
        if not staged.is_dir():
            raise ValueError(f"staged skill path is not a directory: {staged}")
        shutil.rmtree(staged)
    staged.mkdir(parents=True, exist_ok=True)
    for relative in MANAGED_FILES:
        target = staged / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        contents = rendered_skill if relative == "SKILL.md" else files[relative]
        target.write_bytes(contents)

    return staged


def _read_authored_files(source: Path) -> dict[str, bytes]:
    if source.is_symlink() or not source.is_dir():
        raise ValueError(f"missing authored skill directory: {source}")

    files: dict[str, bytes] = {}
    for relative in MANAGED_FILES:
        path = source / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"skill source must contain a regular file: {path}")
        files[relative] = path.read_bytes().replace(b"\r\n", b"\n")
    return files


def _read_tool_count(path: Path) -> int:
    try:
        catalog = json.loads(path.read_text(encoding="utf-8"))
        tools = catalog["tools"]
    except (OSError, KeyError, TypeError, ValueError) as error:
        raise ValueError(f"cannot read MCP tool catalog: {path}") from error
    if not isinstance(tools, list) or not all(isinstance(tool, dict) for tool in tools):
        raise ValueError(f"MCP tool catalog has an invalid tools list: {path}")
    return len(tools)


def _render_skill(source: bytes, tool_count: int) -> bytes:
    text = source.decode("utf-8")
    if TOOL_COUNT_LINE.search(text):
        raise ValueError("authored SKILL.md must not contain generated tool_count metadata")
    if VERSION_LINE.search(text) is None:
        raise ValueError("authored SKILL.md is missing metadata.version")

    text = VERSION_LINE.sub(
        lambda match: f'{match.group(0)}\n  tool_count: {tool_count}',
        text,
        count=1,
    )
    return text.encode("utf-8")
