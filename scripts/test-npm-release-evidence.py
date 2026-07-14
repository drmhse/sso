#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("npm-release-evidence.py")
SPEC = importlib.util.spec_from_file_location("npm_release_evidence", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class NpmReleaseEvidenceTests(unittest.TestCase):
    def fixture(self, root: Path) -> None:
        version = "0.9.0"
        for stem, package_name in MODULE.PACKAGES.items():
            package = json.dumps({"name": package_name, "version": version}).encode()
            with tarfile.open(root / f"{stem}.tgz", "w:gz") as archive:
                info = tarfile.TarInfo("package/package.json")
                info.size = len(package)
                archive.addfile(info, io.BytesIO(package))
            (root / f"{stem}.spdx.json").write_text(
                json.dumps(
                    {"spdxVersion": "SPDX-2.3", "packages": [{"name": package_name}]}
                ),
                encoding="utf-8",
            )
        self.write_checksums(root, MODULE.PAYLOADS)
        MODULE.generate(
            root,
            "v0.9.0",
            "a" * 40,
            "drmhse/AuthOS",
            "https://github.com/drmhse/AuthOS/actions/runs/1",
        )
        self.write_checksums(root, MODULE.PAYLOADS | {MODULE.MANIFEST_NAME})

    @staticmethod
    def write_checksums(root: Path, names: set[str]) -> None:
        (root / MODULE.CHECKSUM_NAME).write_text(
            "".join(f"{sha256(root / name)}  {name}\n" for name in sorted(names)),
            encoding="utf-8",
        )

    def test_accepts_exact_tarballs_sboms_and_manifest(self) -> None:
        with tempfile.TemporaryDirectory(prefix="authos-npm-evidence-") as temp:
            root = Path(temp)
            self.fixture(root)
            MODULE.verify(root)

    def test_rejects_manifest_substitution_even_when_rechecksummed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="authos-npm-evidence-") as temp:
            root = Path(temp)
            self.fixture(root)
            manifest_path = root / MODULE.MANIFEST_NAME
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["packages"][0]["name"] = "@attacker/substitute"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            self.write_checksums(root, MODULE.PAYLOADS | {MODULE.MANIFEST_NAME})
            with self.assertRaisesRegex(ValueError, "mapping mismatch"):
                MODULE.verify(root)

    def test_rejects_tarball_identity_mismatch(self) -> None:
        with tempfile.TemporaryDirectory(prefix="authos-npm-evidence-") as temp:
            root = Path(temp)
            self.fixture(root)
            tarball = root / "authos-node.tgz"
            package = json.dumps(
                {"name": "@drmhse/authos-node", "version": "9.9.9"}
            ).encode()
            with tarfile.open(tarball, "w:gz") as archive:
                info = tarfile.TarInfo("package/package.json")
                info.size = len(package)
                archive.addfile(info, io.BytesIO(package))
            manifest_path = root / MODULE.MANIFEST_NAME
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            entry = next(item for item in manifest["packages"] if item["tarball"] == tarball.name)
            entry["sha256"] = sha256(tarball)
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            self.write_checksums(root, MODULE.PAYLOADS | {MODULE.MANIFEST_NAME})
            with self.assertRaisesRegex(ValueError, "identity mismatch"):
                MODULE.verify(root)

    def test_tarball_work_limits_cover_member_and_expanded_boundaries(self) -> None:
        with tempfile.TemporaryDirectory(prefix="authos-npm-limits-") as temp:
            tarball = Path(temp) / "fixture.tgz"
            package = b'{"name":"fixture","version":"1.0.0"}'
            with tarfile.open(tarball, "w:gz") as archive:
                for name, content in [
                    ("package/package.json", package),
                    ("package/index.js", b"export {}"),
                ]:
                    info = tarfile.TarInfo(name)
                    info.size = len(content)
                    archive.addfile(info, io.BytesIO(content))
            with self.assertRaisesRegex(ValueError, "compressed size limit"):
                MODULE.verify_tarball(
                    tarball, "fixture", "1.0.0", max_compressed_bytes=1
                )
            with self.assertRaisesRegex(ValueError, "member-count limit"):
                MODULE.verify_tarball(tarball, "fixture", "1.0.0", max_members=1)
            with self.assertRaisesRegex(ValueError, "expanded size limit"):
                MODULE.verify_tarball(
                    tarball,
                    "fixture",
                    "1.0.0",
                    max_expanded_bytes=len(package),
                )


if __name__ == "__main__":
    unittest.main()
