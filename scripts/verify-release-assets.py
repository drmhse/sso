#!/usr/bin/env python3
"""Verify downloaded AuthOS standalone release assets without extracting them."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys
import tarfile


REQUIRED_FILES = {
    "install.sh",
    "authos-sqlite-linux-amd64.tar.gz",
    "authos-sqlite-linux-amd64.spdx.json",
    "authos-sqlite-linux-arm64.tar.gz",
    "authos-sqlite-linux-arm64.spdx.json",
    "authos-standalone-release-manifest.json",
}
PAYLOAD_FILES = REQUIRED_FILES - {"authos-standalone-release-manifest.json"}
CHECKSUM_PATTERN = re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]*)$")
MAX_ARCHIVE_COMPRESSED_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_EXPANDED_BYTES = 1024 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 256
MAX_CHECKSUM_BYTES = 64 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_SBOM_BYTES = 32 * 1024 * 1024
REQUIRED_BUNDLE_FILES = {
    "authos",
    "authos.config.example.json",
    "LICENSE",
    "AGPL-3.0.txt",
    "install.sh",
    "README.txt",
    "standalone/authos_standalone.py",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json_limited(path: Path, maximum_bytes: int) -> object:
    if path.stat().st_size > maximum_bytes:
        raise ValueError(f"JSON document exceeds size limit: {path.name}")
    return json.loads(path.read_bytes())


def verify_archive(
    path: Path,
    *,
    max_compressed_bytes: int = MAX_ARCHIVE_COMPRESSED_BYTES,
    max_expanded_bytes: int = MAX_ARCHIVE_EXPANDED_BYTES,
    max_members: int = MAX_ARCHIVE_MEMBERS,
) -> None:
    if path.stat().st_size > max_compressed_bytes:
        raise ValueError(f"archive exceeds compressed size limit: {path.name}")
    with tarfile.open(path, mode="r:gz") as archive:
        members = archive.getmembers()
        if not members:
            raise ValueError(f"archive is empty: {path.name}")
        if len(members) > max_members:
            raise ValueError(f"archive exceeds member-count limit: {path.name}")
        expanded_bytes = sum(max(member.size, 0) for member in members)
        if expanded_bytes > max_expanded_bytes:
            raise ValueError(f"archive exceeds expanded size limit: {path.name}")
        bundle_root = path.name.removesuffix(".tar.gz")
        observed_names: set[str] = set()
        observed_files: set[str] = set()
        for member in members:
            if member.name in observed_names:
                raise ValueError(f"duplicate archive member in {path.name}: {member.name}")
            observed_names.add(member.name)
            raw_name = member.name.rstrip("/") if member.isdir() else member.name
            if any(part in ("", ".", "..") for part in raw_name.split("/")):
                raise ValueError(f"unsafe archive path in {path.name}: {member.name}")
            member_path = PurePosixPath(member.name)
            if member_path.is_absolute() or ".." in member_path.parts:
                raise ValueError(f"unsafe archive path in {path.name}: {member.name}")
            if not (member.isfile() or member.isdir()):
                raise ValueError(f"unsupported special file in {path.name}: {member.name}")
            if not member_path.parts or member_path.parts[0] != bundle_root:
                raise ValueError(f"archive member escapes bundle root in {path.name}: {member.name}")
            if member.isfile():
                observed_files.add(str(PurePosixPath(*member_path.parts[1:])))
        if observed_files != REQUIRED_BUNDLE_FILES:
            missing = sorted(REQUIRED_BUNDLE_FILES - observed_files)
            unexpected = sorted(observed_files - REQUIRED_BUNDLE_FILES)
            raise ValueError(
                f"archive inventory mismatch in {path.name}; missing={missing}, unexpected={unexpected}"
            )


def verify_sbom(path: Path) -> None:
    value = read_json_limited(path, MAX_SBOM_BYTES)
    if not isinstance(value, dict) or value.get("spdxVersion") != "SPDX-2.3":
        raise ValueError(f"not an SPDX 2.3 JSON document: {path.name}")
    packages = value.get("packages")
    if not isinstance(packages, list) or not packages:
        raise ValueError(f"SBOM contains no packages: {path.name}")


def verify_manifest(path: Path, checksums: dict[str, str]) -> None:
    value = read_json_limited(path, MAX_MANIFEST_BYTES)
    if not isinstance(value, dict):
        raise ValueError("release manifest root must be an object")
    if value.get("schemaVersion") != 1 or value.get("scope") != "standalone-linux":
        raise ValueError("release manifest has an unsupported schema or scope")
    source = value.get("source")
    if not isinstance(source, dict):
        raise ValueError("release manifest source is missing")
    tag = source.get("tag")
    commit = source.get("commit")
    repository = source.get("repository")
    workflow_run = source.get("workflowRun")
    if not isinstance(tag, str) or not re.fullmatch(
        r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", tag
    ):
        raise ValueError("release manifest tag is invalid")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("release manifest commit is invalid")
    if repository != "drmhse/AuthOS":
        raise ValueError("release manifest repository is invalid")
    if not isinstance(workflow_run, str) or not workflow_run.startswith(
        "https://github.com/drmhse/AuthOS/actions/runs/"
    ):
        raise ValueError("release manifest workflow run is invalid")

    artifacts = value.get("artifacts")
    if not isinstance(artifacts, list):
        raise ValueError("release manifest artifacts are missing")
    recorded: dict[str, dict[str, object]] = {}
    for entry in artifacts:
        if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
            raise ValueError("release manifest artifact entry is invalid")
        name = entry["name"]
        if name in recorded:
            raise ValueError(f"release manifest duplicates artifact: {name}")
        recorded[name] = entry
    if set(recorded) != PAYLOAD_FILES or len(recorded) != len(artifacts):
        raise ValueError("release manifest payload inventory is not exact")
    for name, entry in recorded.items():
        if entry.get("sha256") != checksums[name]:
            raise ValueError(f"release manifest digest mismatch: {name}")
    for architecture in ("amd64", "arm64"):
        archive = f"authos-sqlite-linux-{architecture}.tar.gz"
        expected_sbom = f"authos-sqlite-linux-{architecture}.spdx.json"
        if recorded[archive].get("sbom") != expected_sbom:
            raise ValueError(f"release manifest SBOM mapping mismatch: {archive}")
    attestation = value.get("attestation")
    if not isinstance(attestation, dict) or attestation != {
        "provider": "github-artifact-attestations",
        "workflow": "drmhse/AuthOS/.github/workflows/release.yml",
    }:
        raise ValueError("release manifest attestation policy is invalid")


def verify_directory(directory: Path) -> None:
    directory = directory.expanduser().resolve(strict=True)
    expected_directory_entries = REQUIRED_FILES | {"SHA256SUMS.txt"}
    actual_directory_entries = {entry.name for entry in directory.iterdir()}
    if actual_directory_entries != expected_directory_entries:
        missing = sorted(expected_directory_entries - actual_directory_entries)
        unexpected = sorted(actual_directory_entries - expected_directory_entries)
        raise ValueError(
            f"release directory inventory mismatch; missing={missing}, unexpected={unexpected}"
        )
    for entry in directory.iterdir():
        if entry.is_symlink() or not entry.is_file():
            raise ValueError(f"release directory entry is not a regular file: {entry.name}")
    checksum_file = directory / "SHA256SUMS.txt"
    if not checksum_file.is_file():
        raise ValueError("missing SHA256SUMS.txt")
    if checksum_file.stat().st_size > MAX_CHECKSUM_BYTES:
        raise ValueError("SHA256SUMS.txt exceeds size limit")

    checksums: dict[str, str] = {}
    for line_number, line in enumerate(
        checksum_file.read_text(encoding="utf-8").splitlines(), start=1
    ):
        match = CHECKSUM_PATTERN.fullmatch(line)
        if match is None:
            raise ValueError(f"malformed checksum line {line_number}")
        digest, filename = match.groups()
        if filename in checksums:
            raise ValueError(f"duplicate checksum entry: {filename}")
        checksums[filename] = digest

    if set(checksums) != REQUIRED_FILES:
        missing = sorted(REQUIRED_FILES - set(checksums))
        unexpected = sorted(set(checksums) - REQUIRED_FILES)
        raise ValueError(
            f"checksum inventory mismatch; missing={missing}, unexpected={unexpected}"
        )

    for filename, expected in checksums.items():
        path = directory / filename
        if not path.is_file():
            raise ValueError(f"missing release asset: {filename}")
        if sha256_file(path) != expected:
            raise ValueError(f"SHA-256 mismatch: {filename}")

    for architecture in ("amd64", "arm64"):
        verify_archive(directory / f"authos-sqlite-linux-{architecture}.tar.gz")
        verify_sbom(directory / f"authos-sqlite-linux-{architecture}.spdx.json")
    verify_manifest(directory / "authos-standalone-release-manifest.json", checksums)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    try:
        verify_directory(args.directory)
    except (OSError, json.JSONDecodeError, tarfile.TarError, ValueError) as error:
        print(f"AuthOS release verification failed: {error}", file=sys.stderr)
        return 1
    print("AuthOS standalone release assets verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
