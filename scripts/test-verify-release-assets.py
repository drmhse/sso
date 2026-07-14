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


SCRIPT = Path(__file__).with_name("verify-release-assets.py")
SPEC = importlib.util.spec_from_file_location("verify_release_assets", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ReleaseVerifierTests(unittest.TestCase):
    def fixture(self, root: Path, unsafe_archive: bool = False) -> None:
        (root / "install.sh").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        sbom = {"spdxVersion": "SPDX-2.3", "packages": [{"name": "authos"}]}
        for architecture in ("amd64", "arm64"):
            archive_path = root / f"authos-sqlite-linux-{architecture}.tar.gz"
            with tarfile.open(archive_path, "w:gz") as archive:
                bundle_root = archive_path.name.removesuffix(".tar.gz")
                for relative in sorted(MODULE.REQUIRED_BUNDLE_FILES):
                    content = b"binary"
                    name = (
                        "../escape"
                        if unsafe_archive and architecture == "amd64" and relative == "authos"
                        else f"{bundle_root}/{relative}"
                    )
                    info = tarfile.TarInfo(name=name)
                    info.size = len(content)
                    archive.addfile(info, io.BytesIO(content))
            (root / f"authos-sqlite-linux-{architecture}.spdx.json").write_text(
                json.dumps(sbom), encoding="utf-8"
            )

        payloads = sorted(MODULE.PAYLOAD_FILES)
        manifest = {
            "schemaVersion": 1,
            "scope": "standalone-linux",
            "source": {
                "repository": "drmhse/AuthOS",
                "tag": "v0.9.0",
                "commit": "a" * 40,
                "workflowRun": "https://github.com/drmhse/AuthOS/actions/runs/1",
            },
            "artifacts": [
                {
                    "name": filename,
                    "sha256": sha256(root / filename),
                    **(
                        {"sbom": filename.removesuffix(".tar.gz") + ".spdx.json"}
                        if filename.endswith(".tar.gz")
                        else {}
                    ),
                }
                for filename in payloads
            ],
            "attestation": {
                "provider": "github-artifact-attestations",
                "workflow": "drmhse/AuthOS/.github/workflows/release.yml",
            },
        }
        (root / "authos-standalone-release-manifest.json").write_text(
            json.dumps(manifest), encoding="utf-8"
        )

        lines = []
        for filename in sorted(MODULE.REQUIRED_FILES):
            lines.append(f"{sha256(root / filename)}  {filename}")
        (root / "SHA256SUMS.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

    def test_accepts_complete_safe_release_set(self) -> None:
        with tempfile.TemporaryDirectory(prefix="authos-release-test-") as temp:
            root = Path(temp)
            self.fixture(root)
            MODULE.verify_directory(root)

    def test_rejects_checksum_tampering(self) -> None:
        with tempfile.TemporaryDirectory(prefix="authos-release-test-") as temp:
            root = Path(temp)
            self.fixture(root)
            (root / "install.sh").write_text("tampered\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                MODULE.verify_directory(root)

    def test_rejects_unexpected_prepared_artifact(self) -> None:
        with tempfile.TemporaryDirectory(prefix="authos-release-test-") as temp:
            root = Path(temp)
            self.fixture(root)
            (root / "untracked.sha256").write_text("unexpected\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "directory inventory mismatch"):
                MODULE.verify_directory(root)

    def test_rejects_archive_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory(prefix="authos-release-test-") as temp:
            root = Path(temp)
            self.fixture(root, unsafe_archive=True)
            with self.assertRaisesRegex(ValueError, "unsafe archive path"):
                MODULE.verify_directory(root)

    def test_rejects_archive_link_and_duplicate_member(self) -> None:
        for mode in ("link", "duplicate"):
            with self.subTest(mode=mode):
                with tempfile.TemporaryDirectory(prefix="authos-release-test-") as temp:
                    archive_path = Path(temp) / "authos-sqlite-linux-amd64.tar.gz"
                    bundle_root = archive_path.name.removesuffix(".tar.gz")
                    with tarfile.open(archive_path, "w:gz") as archive:
                        for relative in sorted(MODULE.REQUIRED_BUNDLE_FILES):
                            content = b"binary"
                            info = tarfile.TarInfo(f"{bundle_root}/{relative}")
                            info.size = len(content)
                            archive.addfile(info, io.BytesIO(content))
                        if mode == "link":
                            info = tarfile.TarInfo(f"{bundle_root}/linked")
                            info.type = tarfile.SYMTYPE
                            info.linkname = "/etc/passwd"
                            archive.addfile(info)
                        else:
                            content = b"duplicate"
                            info = tarfile.TarInfo(f"{bundle_root}/authos")
                            info.size = len(content)
                            archive.addfile(info, io.BytesIO(content))
                    expected = "unsupported special file" if mode == "link" else "duplicate archive member"
                    with self.assertRaisesRegex(ValueError, expected):
                        MODULE.verify_archive(archive_path)


    def test_archive_work_limits_cover_member_and_expanded_boundaries(self) -> None:
        with tempfile.TemporaryDirectory(prefix="authos-release-limits-") as temp:
            archive_path = Path(temp) / "fixture.tar.gz"
            with tarfile.open(archive_path, "w:gz") as archive:
                for name, content in [("one", b"123"), ("two", b"456")]:
                    info = tarfile.TarInfo(name)
                    info.size = len(content)
                    archive.addfile(info, io.BytesIO(content))
            with self.assertRaisesRegex(ValueError, "compressed size limit"):
                MODULE.verify_archive(archive_path, max_compressed_bytes=1)
            with self.assertRaisesRegex(ValueError, "member-count limit"):
                MODULE.verify_archive(archive_path, max_members=1)
            with self.assertRaisesRegex(ValueError, "expanded size limit"):
                MODULE.verify_archive(archive_path, max_members=2, max_expanded_bytes=5)

    def test_json_metadata_size_limit_is_checked_before_parsing(self) -> None:
        with tempfile.TemporaryDirectory(prefix="authos-release-json-") as temp:
            path = Path(temp) / "metadata.json"
            path.write_text('{"value":1}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "JSON document exceeds size limit"):
                MODULE.read_json_limited(path, 2)

    def test_rejects_manifest_digest_substitution_even_with_valid_file_checksums(self) -> None:
        with tempfile.TemporaryDirectory(prefix="authos-release-test-") as temp:
            root = Path(temp)
            self.fixture(root)
            manifest_path = root / "authos-standalone-release-manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["artifacts"][0]["sha256"] = "0" * 64
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            lines = []
            for filename in sorted(MODULE.REQUIRED_FILES):
                lines.append(f"{sha256(root / filename)}  {filename}")
            (root / "SHA256SUMS.txt").write_text(
                "\n".join(lines) + "\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(ValueError, "manifest digest mismatch"):
                MODULE.verify_directory(root)


if __name__ == "__main__":
    unittest.main()
