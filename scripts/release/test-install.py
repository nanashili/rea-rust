#!/usr/bin/env python3
"""Black-box tests for the standalone release installer.

These tests exercise the installer at its user-facing boundary. The fake curl
only maps release URLs to local fixtures; no production transport option is
changed to make the installer accept insecure downloads.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[2]
INSTALLER = REPOSITORY / "install.sh"
TARGET = "x86_64-unknown-linux-gnu"
VERSION = "6.7.0"


class InstallerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="rea-install-test-"))
        self.release = self.root / "release"
        self.release.mkdir()
        self.verify_marker = self.root / "verify-called"
        self.fake_bin = self.root / "bin"
        self.fake_bin.mkdir()
        self._write_fake_curl()
        self._write_fake_uname()
        self._write_fake_mv()
        self._write_release()

    def tearDown(self) -> None:
        shutil.rmtree(self.root)

    def _write_fake_curl(self) -> None:
        script = self.fake_bin / "curl"
        script.write_text(
            "#!/bin/sh\n"
            "set -eu\n"
            "output=\n"
            "url=\n"
            "while [ $# -gt 0 ]; do\n"
            "  case $1 in\n"
            "    --output) output=$2; shift 2 ;;\n"
            "    http*) url=$1; shift ;;\n"
            "    *) shift ;;\n"
            "  esac\n"
            "done\n"
            "file=${url##*/}\n"
            "cp \"$REA_TEST_RELEASE/$file\" \"$output\"\n"
        )
        script.chmod(0o755)

    def _write_fake_uname(self) -> None:
        script = self.fake_bin / "uname"
        script.write_text(
            "#!/bin/sh\n"
            "case ${1:-} in\n"
            "  -s) printf '%s\\n' Linux ;;\n"
            "  -m) printf '%s\\n' x86_64 ;;\n"
            "  *) exit 1 ;;\n"
            "esac\n"
        )
        script.chmod(0o755)

    def _write_fake_mv(self) -> None:
        script = self.fake_bin / "mv"
        script.write_text(
            "#!/bin/sh\n"
            "set -eu\n"
            "destination=\n"
            "for argument do destination=$argument; done\n"
            "case ${REA_TEST_FAIL_ACTIVATION:-}:${destination:-} in\n"
            "  1:*/rea) exit 1 ;;\n"
            "esac\n"
            "exec /bin/mv \"$@\"\n"
        )
        script.chmod(0o755)

    def _write_release(self) -> None:
        payload = self.root / "payload" / "rea-rust"
        (payload / "bin").mkdir(parents=True)
        (payload / "release.json").write_text(
            '{"version":"6.7.0","target":"x86_64-unknown-linux-gnu"}\n'
        )
        (payload / "VERSION").write_text("6.7.0\n")
        for name, body in {
            "rea": (
                "#!/bin/sh\n"
                "case ${1:-} in\n"
                "  --version) printf '%s\\n' \"${REA_TEST_VERSION:-6.7.0}\" ;;\n"
                "  --verify-installation) touch \"$REA_TEST_VERIFY_MARKER\"; exit 0 ;;\n"
                "  *) exit 1 ;;\n"
                "esac\n"
            ),
            "rea-ghidra-rust-worker": "#!/bin/sh\nexit 0\n",
        }.items():
            path = payload / "bin" / name
            path.write_text(body)
            path.chmod(0o755)

        archive = self.release / f"rea-rust-{TARGET}.tar.gz"
        with tarfile.open(archive, "w:gz") as handle:
            handle.add(payload, arcname="rea-rust")
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        (self.release / "SHA256SUMS").write_text(
            f"{digest}  rea-rust-{TARGET}.tar.gz\n"
        )

    def _refresh_release(self) -> None:
        payload = self.root / "payload" / "rea-rust"
        archive = self.release / f"rea-rust-{TARGET}.tar.gz"
        with tarfile.open(archive, "w:gz") as handle:
            handle.add(payload, arcname="rea-rust")
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        (self.release / "SHA256SUMS").write_text(
            f"{digest}  rea-rust-{TARGET}.tar.gz\n"
        )

    def _run(self, *, version: str = VERSION, mutate_release=None, paths_with_spaces: bool = False, fail_activation: bool = False) -> subprocess.CompletedProcess[str]:
        if mutate_release:
            mutate_release()
        suffix = " path" if paths_with_spaces else ""
        install_root = self.root / f"data{suffix}"
        bin_dir = self.root / f"user-bin{suffix}"
        env = os.environ.copy()
        env.update(
            {
                "PATH": f"{self.fake_bin}:{env['PATH']}",
                "REA_TEST_RELEASE": str(self.release),
                "REA_TEST_VERIFY_MARKER": str(self.verify_marker),
                "REA_TEST_VERSION": version.removeprefix("v"),
                "REA_REPOSITORY": "test/repository",
                "REA_VERSION": version,
                "REA_INSTALL_ROOT": str(install_root),
                "REA_BIN_DIR": str(bin_dir),
                "REA_TEST_FAIL_ACTIVATION": "1" if fail_activation else "",
            }
        )
        return subprocess.run(
            [str(INSTALLER)],
            text=True,
            capture_output=True,
            env=env,
            check=False,
        )

    def test_installs_and_activates_both_executables(self) -> None:
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.verify_marker.exists())
        self.assertEqual((self.root / "user-bin" / "rea").resolve().name, "rea")
        self.assertEqual(
            (self.root / "data" / "versions" / VERSION / TARGET / "bin" / "rea-ghidra-rust-worker").resolve().name,
            "rea-ghidra-rust-worker",
        )
        manifest = self.root / "data" / "versions" / VERSION / TARGET / ".rea-rust-install"
        self.assertIn("version=6.7.0", manifest.read_text())

    def test_bad_checksum_does_not_touch_existing_install(self) -> None:
        first = self._run()
        self.assertEqual(first.returncode, 0, first.stderr)
        rea_link = self.root / "user-bin" / "rea"
        old_target = os.readlink(rea_link)
        checksum = self.release / "SHA256SUMS"
        checksum.write_text("0" * 64 + f"  rea-rust-{TARGET}.tar.gz\n")
        result = self._run()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(os.readlink(rea_link), old_target)

    def test_same_version_is_idempotent(self) -> None:
        first = self._run()
        self.assertEqual(first.returncode, 0, first.stderr)
        second = self._run()
        self.assertEqual(second.returncode, 0, second.stderr)

    def test_accepts_prerelease_and_build_metadata(self) -> None:
        version = "6.7.0-rc.1+build.7"
        payload = self.root / "payload" / "rea-rust"
        (payload / "VERSION").write_text(f"{version}\n")
        (payload / "release.json").write_text(
            f'{{"version":"{version}","target":"{TARGET}"}}\n'
        )
        self._refresh_release()
        result = self._run(version=version)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(
            (self.root / "data" / "versions" / version / TARGET / "bin" / "rea").exists()
        )

    def test_install_root_with_spaces(self) -> None:
        result = self._run(paths_with_spaces=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.root / "data path" / "versions" / VERSION / TARGET / "bin" / "rea").exists())

    def test_refuses_unrelated_binary(self) -> None:
        bin_dir = self.root / "user-bin"
        bin_dir.mkdir()
        (bin_dir / "rea").write_text("user binary\n")
        result = self._run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refusing to overwrite existing file", result.stderr)

    def test_refuses_foreign_symlink(self) -> None:
        bin_dir = self.root / "user-bin"
        bin_dir.mkdir()
        foreign = self.root / "foreign-rea"
        foreign.write_text("foreign\n")
        (bin_dir / "rea").symlink_to(foreign)
        result = self._run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unrelated symlink", result.stderr)

    def test_refuses_symlinked_versions_directory(self) -> None:
        install_root = self.root / "data"
        install_root.mkdir()
        outside = self.root / "outside"
        outside.mkdir()
        (install_root / "versions").symlink_to(outside, target_is_directory=True)
        result = self._run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("symlinked versions directory", result.stderr)

    def test_refuses_symlinked_existing_version_directory(self) -> None:
        first = self._run()
        self.assertEqual(first.returncode, 0, first.stderr)
        version_dir = self.root / "data" / "versions" / VERSION / TARGET
        outside = self.root / "outside-version"
        version_dir.rename(outside)
        version_dir.symlink_to(outside, target_is_directory=True)
        result = self._run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("symlinked installation directory", result.stderr)

    def test_activation_failure_preserves_previous_owned_link(self) -> None:
        first = self._run()
        self.assertEqual(first.returncode, 0, first.stderr)
        old_root = self.root / "data" / "versions" / "5.0.0" / TARGET
        (old_root / "bin").mkdir(parents=True)
        for name in ("rea", "rea-ghidra-rust-worker"):
            source = self.root / f"old-{name}"
            source.write_text("old\n")
            source.chmod(0o755)
            shutil.copy2(source, old_root / "bin" / name)
        (old_root / ".rea-rust-install").write_text(
            f"version=5.0.0\ntarget={TARGET}\nrepository=nanashili/rea-rust\n"
        )
        link = self.root / "user-bin" / "rea"
        link.unlink()
        link.symlink_to(old_root / "bin" / "rea")
        result = self._run(fail_activation=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(os.readlink(link), str(old_root / "bin" / "rea"))

    def test_rejects_archive_symlink_before_extraction(self) -> None:
        archive = self.release / f"rea-rust-{TARGET}.tar.gz"
        payload = self.root / "payload" / "rea-rust"
        with tarfile.open(archive, "w:gz") as handle:
            handle.add(payload, arcname="rea-rust")
            link = tarfile.TarInfo("rea-rust/bin/escape")
            link.type = tarfile.SYMTYPE
            link.linkname = "../../outside"
            handle.addfile(link)
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        (self.release / "SHA256SUMS").write_text(
            f"{digest}  rea-rust-{TARGET}.tar.gz\n"
        )
        result = self._run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("symlink, hard link, or special file", result.stderr)

    def test_rejects_invalid_requested_version_before_download(self) -> None:
        result = self._run(version="latest; rm -rf /")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("REA_VERSION must be a semantic version", result.stderr)


if __name__ == "__main__":
    unittest.main()
