#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("generate-release-manifest.py")
SPEC = importlib.util.spec_from_file_location("generate_release_manifest", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ReleaseManifestGeneratorTests(unittest.TestCase):
    def test_generates_exact_payload_and_sbom_relationships(self) -> None:
        checksums = {name: f"{index:064x}" for index, name in enumerate(MODULE.PAYLOADS, 1)}
        value = MODULE.generate(
            checksums,
            "v0.9.0-rc.1",
            "a" * 40,
            "drmhse/AuthOS",
            "https://github.com/drmhse/AuthOS/actions/runs/1",
        )
        self.assertEqual(value["scope"], "standalone-linux")
        artifacts = {entry["name"]: entry for entry in value["artifacts"]}
        self.assertEqual(set(artifacts), set(MODULE.PAYLOADS))
        self.assertEqual(
            artifacts["authos-sqlite-linux-amd64.tar.gz"]["sbom"],
            "authos-sqlite-linux-amd64.spdx.json",
        )

    def test_rejects_ambiguous_source_identity(self) -> None:
        checksums = {name: "a" * 64 for name in MODULE.PAYLOADS}
        with self.assertRaisesRegex(ValueError, "tag"):
            MODULE.generate(
                checksums,
                "latest",
                "a" * 40,
                "drmhse/AuthOS",
                "https://github.com/drmhse/AuthOS/actions/runs/1",
            )
        with self.assertRaisesRegex(ValueError, "commit"):
            MODULE.generate(
                checksums,
                "v0.9.0",
                "short",
                "drmhse/AuthOS",
                "https://github.com/drmhse/AuthOS/actions/runs/1",
            )

    def test_checksum_input_requires_exact_payload_set(self) -> None:
        with tempfile.TemporaryDirectory(prefix="authos-manifest-test-") as temp:
            checksum_file = Path(temp) / "SHA256SUMS.txt"
            checksum_file.write_text(f"{'a' * 64}  install.sh\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "exact standalone payload"):
                MODULE.read_checksums(checksum_file)


if __name__ == "__main__":
    unittest.main()
