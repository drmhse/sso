#!/usr/bin/env python3
"""Generate or verify durable AuthOS npm release evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys
import tarfile


PACKAGES = {
    "sso-sdk": "@drmhse/sso-sdk",
    "authos-node": "@drmhse/authos-node",
    "authos-react": "@drmhse/authos-react",
    "authos-vue": "@drmhse/authos-vue",
    "authos-cli": "@drmhse/authos-cli",
}
PAYLOADS = {
    filename
    for stem in PACKAGES
    for filename in (f"{stem}.tgz", f"{stem}.spdx.json")
}
MANIFEST_NAME = "authos-npm-release-manifest.json"
CHECKSUM_NAME = "npm-SHA256SUMS.txt"
CHECKSUM_PATTERN = re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]*)$")
MAX_CHECKSUM_BYTES = 64 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_SBOM_BYTES = 32 * 1024 * 1024


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


def read_checksums(path: Path, expected: set[str]) -> dict[str, str]:
    if path.stat().st_size > MAX_CHECKSUM_BYTES:
        raise ValueError("npm checksum input exceeds size limit")
    checksums: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = CHECKSUM_PATTERN.fullmatch(line)
        if match is None:
            raise ValueError("npm checksum input is malformed")
        digest, name = match.groups()
        if name in checksums:
            raise ValueError(f"duplicate npm checksum entry: {name}")
        checksums[name] = digest
    if set(checksums) != expected:
        raise ValueError("npm checksum input does not contain the exact evidence set")
    return checksums


def generate(directory: Path, tag: str, commit: str, repository: str, workflow_run: str) -> None:
    checksums = read_checksums(directory / CHECKSUM_NAME, PAYLOADS)
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", tag):
        raise ValueError("npm evidence tag is not v-prefixed SemVer")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("npm evidence commit must be a full lowercase Git SHA")
    if repository != "drmhse/AuthOS" or not workflow_run.startswith(
        "https://github.com/drmhse/AuthOS/actions/runs/"
    ):
        raise ValueError("npm evidence source identity is invalid")

    version = tag.removeprefix("v")
    packages = []
    for stem, name in sorted(PACKAGES.items()):
        tarball = f"{stem}.tgz"
        sbom = f"{stem}.spdx.json"
        packages.append(
            {
                "name": name,
                "version": version,
                "tarball": tarball,
                "sha256": checksums[tarball],
                "sbom": sbom,
                "sbomSha256": checksums[sbom],
            }
        )
    manifest = {
        "schemaVersion": 1,
        "scope": "npm-packages",
        "source": {
            "repository": repository,
            "tag": tag,
            "commit": commit,
            "workflowRun": workflow_run,
        },
        "packages": packages,
        "attestation": {
            "provider": "github-artifact-attestations-and-npm-provenance",
            "workflow": f"{repository}/.github/workflows/publish-npm-packages.yml",
        },
    }
    (directory / MANIFEST_NAME).write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


MAX_TARBALL_COMPRESSED_BYTES = 32 * 1024 * 1024
MAX_TARBALL_EXPANDED_BYTES = 128 * 1024 * 1024
MAX_TARBALL_MEMBERS = 4096
MAX_PACKAGE_JSON_BYTES = 1024 * 1024


def verify_tarball(
    path: Path,
    expected_name: str,
    expected_version: str,
    *,
    max_compressed_bytes: int = MAX_TARBALL_COMPRESSED_BYTES,
    max_expanded_bytes: int = MAX_TARBALL_EXPANDED_BYTES,
    max_members: int = MAX_TARBALL_MEMBERS,
) -> None:
    if path.stat().st_size > max_compressed_bytes:
        raise ValueError(f"npm tarball exceeds compressed size limit: {path.name}")
    with tarfile.open(path, "r:gz") as archive:
        members = archive.getmembers()
        if not members or len(members) > max_members:
            raise ValueError(f"npm tarball exceeds member-count limit: {path.name}")
        if sum(max(member.size, 0) for member in members) > max_expanded_bytes:
            raise ValueError(f"npm tarball exceeds expanded size limit: {path.name}")
        for member in members:
            member_path = PurePosixPath(member.name)
            if member_path.is_absolute() or ".." in member_path.parts or member.isdev() or member.isfifo():
                raise ValueError(f"unsafe npm tarball member: {path.name}")
        try:
            package_member = archive.getmember("package/package.json")
        except KeyError as error:
            raise ValueError(
                f"npm tarball has no package.json: {path.name}"
            ) from error
        if package_member.size > MAX_PACKAGE_JSON_BYTES:
            raise ValueError(f"npm package.json exceeds size limit: {path.name}")
        package_json = archive.extractfile("package/package.json")
        if package_json is None:
            raise ValueError(f"npm tarball has no package.json: {path.name}")
        package_bytes = package_json.read(MAX_PACKAGE_JSON_BYTES + 1)
        if len(package_bytes) > MAX_PACKAGE_JSON_BYTES:
            raise ValueError(f"npm package.json exceeds size limit: {path.name}")
        value = json.loads(package_bytes)
    if value.get("name") != expected_name or value.get("version") != expected_version:
        raise ValueError(f"npm tarball identity mismatch: {path.name}")


def verify(directory: Path) -> None:
    checksums = read_checksums(directory / CHECKSUM_NAME, PAYLOADS | {MANIFEST_NAME})
    for name, expected in checksums.items():
        path = directory / name
        if not path.is_file() or sha256_file(path) != expected:
            raise ValueError(f"npm evidence SHA-256 mismatch: {name}")

    manifest = read_json_limited(directory / MANIFEST_NAME, MAX_MANIFEST_BYTES)
    if not isinstance(manifest, dict) or manifest.get("schemaVersion") != 1 or manifest.get("scope") != "npm-packages":
        raise ValueError("npm evidence manifest schema is invalid")
    source = manifest.get("source")
    if not isinstance(source, dict):
        raise ValueError("npm evidence source is missing")
    tag = source.get("tag")
    commit = source.get("commit")
    if not isinstance(tag, str) or not re.fullmatch(
        r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", tag
    ):
        raise ValueError("npm evidence tag is invalid")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("npm evidence commit is invalid")
    if source.get("repository") != "drmhse/AuthOS" or not str(source.get("workflowRun", "")).startswith(
        "https://github.com/drmhse/AuthOS/actions/runs/"
    ):
        raise ValueError("npm evidence source identity is invalid")

    entries = manifest.get("packages")
    if not isinstance(entries, list):
        raise ValueError("npm evidence package inventory is missing")
    by_tarball: dict[str, dict[str, object]] = {}
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("tarball"), str):
            raise ValueError("npm evidence package entry is invalid")
        if entry["tarball"] in by_tarball:
            raise ValueError("npm evidence package entry is duplicated")
        by_tarball[entry["tarball"]] = entry
    expected_tarballs = {f"{stem}.tgz" for stem in PACKAGES}
    if set(by_tarball) != expected_tarballs:
        raise ValueError("npm evidence package inventory is not exact")

    version = tag.removeprefix("v")
    for stem, package_name in PACKAGES.items():
        tarball = f"{stem}.tgz"
        sbom = f"{stem}.spdx.json"
        entry = by_tarball[tarball]
        if entry != {
            "name": package_name,
            "version": version,
            "tarball": tarball,
            "sha256": checksums[tarball],
            "sbom": sbom,
            "sbomSha256": checksums[sbom],
        }:
            raise ValueError(f"npm evidence mapping mismatch: {tarball}")
        verify_tarball(directory / tarball, package_name, version)
        sbom_value = read_json_limited(directory / sbom, MAX_SBOM_BYTES)
        if not isinstance(sbom_value, dict) or sbom_value.get("spdxVersion") != "SPDX-2.3" or not sbom_value.get("packages"):
            raise ValueError(f"npm SPDX document is invalid: {sbom}")


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    generate_parser = subparsers.add_parser("generate")
    generate_parser.add_argument("directory", type=Path)
    generate_parser.add_argument("--tag", required=True)
    generate_parser.add_argument("--commit", required=True)
    generate_parser.add_argument("--repository", required=True)
    generate_parser.add_argument("--workflow-run", required=True)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    try:
        directory = args.directory.resolve(strict=True)
        if args.command == "generate":
            generate(directory, args.tag, args.commit, args.repository, args.workflow_run)
        else:
            verify(directory)
    except (OSError, ValueError, json.JSONDecodeError, tarfile.TarError) as error:
        print(f"AuthOS npm release evidence failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
