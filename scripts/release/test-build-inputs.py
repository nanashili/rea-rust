#!/usr/bin/env python3
"""Check worker cache invalidation against committed Git trees."""

from pathlib import Path
import subprocess
import tempfile
import unittest

from build_inputs import worker_fingerprint


class WorkerCacheInputsTest(unittest.TestCase):
    def test_tracks_source_paths_contents_and_configuration(self):
        with tempfile.TemporaryDirectory(prefix="rea-worker-inputs-") as temporary:
            root = Path(temporary)
            self.git(root, "init", "--quiet")
            source = root / "ghidra-rust-worker/src/main.rs"
            source.parent.mkdir(parents=True)
            source.write_text("fn main() {}\n", encoding="utf-8")
            self.commit(root)
            baseline = worker_fingerprint(root)

            (root / "README.md").write_text("documentation\n", encoding="utf-8")
            self.commit(root)
            self.assertEqual(worker_fingerprint(root), baseline)

            source.rename(source.with_name("renamed.rs"))
            self.commit(root)
            renamed = worker_fingerprint(root)
            self.assertNotEqual(renamed, baseline)

            source = source.with_name("renamed.rs")
            source.write_text("fn main() { println!(\"changed\"); }\n", encoding="utf-8")
            self.commit(root)
            changed = worker_fingerprint(root)
            self.assertNotEqual(changed, renamed)

            configuration = root / ".cargo/config.toml"
            configuration.parent.mkdir()
            configuration.write_text("[build]\njobs = 2\n", encoding="utf-8")
            self.commit(root)
            configured = worker_fingerprint(root)
            self.assertNotEqual(configured, changed)

            source.unlink()
            self.commit(root)
            self.assertNotEqual(worker_fingerprint(root), configured)

    @staticmethod
    def git(root, *arguments):
        subprocess.run(
            ["git", *arguments], cwd=root, check=True, capture_output=True, text=True
        )

    def commit(self, root):
        self.git(root, "add", "--all")
        self.git(
            root,
            "-c", "user.name=Cache input test",
            "-c", "user.email=cache-test@example.invalid",
            "-c", "commit.gpgsign=false",
            "commit", "--quiet", "-m", "fixture",
        )


if __name__ == "__main__":
    unittest.main()
