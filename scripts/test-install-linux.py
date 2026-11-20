#!/usr/bin/env python3
"""Exercise the curl-to-bash installer without downloading or installing as root."""

import hashlib
import os
from pathlib import Path

import subprocess
import tempfile
import unittest

INSTALLER = Path(__file__).with_name("install-linux.sh")
FIXTURE = b"test-only Debian package\n"


class InstallTests(unittest.TestCase):
    def run_installer(self, *, arch="amd64", corrupt=False, truncate=False, bad_manifest=False):
        script = INSTALLER.read_text(encoding="utf-8")
        if truncate:
            script = script.rsplit("\n}", 1)[0]

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / "apt-called"
            fixture = root / "fixture"
            fixture.write_bytes(b"corrupt" if corrupt else FIXTURE)
            commands = {
                "apt-get": 'printf "%s\\n" "$1" >> "$APT_MARKER"',
                "curl": '''while [[ $1 != -o ]]; do shift; done
if [[ $3 == */SHA256SUMS.txt ]]; then
    base=${3%/*}; version=${base##*/v}
    printf '%s  aevan_%s_amd64.deb\\n' "$CHECKSUM" "$version" > "$2"
else
    cp "$FIXTURE" "$2"
fi''',
                "dpkg": 'printf "%s\\n" "$TEST_ARCH"',
                "sudo": '"$@"',
            }
            for name, body in commands.items():
                path = root / name
                path.write_text("#!/bin/bash\n" + body + "\n", encoding="utf-8")
                path.chmod(0o755)

            result = subprocess.run(
                ["bash"], input=script, text=True, capture_output=True, check=False,
                env={**os.environ, "PATH": f"{root}:{os.environ['PATH']}",
                     "APT_MARKER": str(marker), "FIXTURE": str(fixture), "TEST_ARCH": arch,
                     "CHECKSUM": "invalid" if bad_manifest else hashlib.sha256(FIXTURE).hexdigest()},
            )
            calls = marker.read_text().splitlines() if marker.exists() else []
        return result, calls

    def test_verified_download_reaches_apt(self):
        result, calls = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, ["update", "install"])

    def test_corrupt_download_never_reaches_apt(self):
        result, calls = self.run_installer(corrupt=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("checksum", result.stderr.lower())
        self.assertEqual(calls, [])

    def test_arm64_never_reaches_apt(self):
        result, calls = self.run_installer(arch="arm64")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("amd64", result.stderr)
        self.assertEqual(calls, [])

    def test_bad_manifest_never_reaches_apt(self):
        result, calls = self.run_installer(bad_manifest=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("checksum", result.stderr.lower())
        self.assertEqual(calls, [])

    def test_truncated_script_never_reaches_apt(self):
        result, calls = self.run_installer(truncate=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
