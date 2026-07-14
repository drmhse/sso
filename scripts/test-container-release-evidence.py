#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


SCRIPT = Path(__file__).with_name("container-release-evidence.py")
SPEC = importlib.util.spec_from_file_location("container_release_evidence", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ContainerReleaseEvidenceTests(unittest.TestCase):
    def test_round_trip_all_backends(self) -> None:
        for backend in MODULE.BACKENDS:
            value = MODULE.record(
                backend,
                f"sha256:{'a' * 64}",
                "v0.9.0",
                "b" * 40,
                "https://github.com/drmhse/AuthOS/actions/runs/1",
            )
            MODULE.verify(value)

    def test_rejects_mutable_or_malformed_identity(self) -> None:
        with self.assertRaisesRegex(ValueError, "digest"):
            MODULE.record(
                "sqlite",
                "latest",
                "v0.9.0",
                "b" * 40,
                "https://github.com/drmhse/AuthOS/actions/runs/1",
            )

    def test_detects_field_substitution(self) -> None:
        value = MODULE.record(
            "mysql",
            f"sha256:{'a' * 64}",
            "v0.9.0",
            "b" * 40,
            "https://github.com/drmhse/AuthOS/actions/runs/1",
        )
        value["tag"] = "latest"
        with self.assertRaisesRegex(ValueError, "inconsistent"):
            MODULE.verify(value)


if __name__ == "__main__":
    unittest.main()
