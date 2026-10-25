#!/usr/bin/env python3
"""Identify the tracked inputs and runner image for worker binary reuse."""

import hashlib
import os
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[2]
WORKER_INPUTS = (
    "ghidra-rust-worker",
    ".cargo",
    "rust-toolchain.toml",
    ".github/workflows/release.yml",
    "scripts/release/build_inputs.py",
)


def worker_fingerprint(root: Path) -> str:
    # Git tree entries include paths, file modes, and content identities. In CI
    # the clean checkout is HEAD, so renames and deletions invalidate reuse too.
    entries = subprocess.check_output(
        ["git", "ls-tree", "-rz", "HEAD", "--", *WORKER_INPUTS], cwd=root
    )
    if not entries:
        raise ValueError("worker build inputs must not be empty")
    return hashlib.sha256(entries).hexdigest()


def main() -> None:
    image = f"{os.environ['ImageOS']}-{os.environ['ImageVersion']}"
    fingerprint = worker_fingerprint(ROOT)
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
        output.write(f"image={image}\nworker-inputs={fingerprint}\n")


if __name__ == "__main__":
    main()
