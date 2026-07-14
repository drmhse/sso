#!/usr/bin/env python3
"""Generate the standalone AuthOS release evidence manifest."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re


CHECKSUM_PATTERN = re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]*)$")
PAYLOADS = {
    "install.sh": None,
    "authos-sqlite-linux-amd64.tar.gz": "authos-sqlite-linux-amd64.spdx.json",
    "authos-sqlite-linux-amd64.spdx.json": None,
    "authos-sqlite-linux-arm64.tar.gz": "authos-sqlite-linux-arm64.spdx.json",
    "authos-sqlite-linux-arm64.spdx.json": None,
}


def read_checksums(path: Path) -> dict[str, str]:
    checksums: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = CHECKSUM_PATTERN.fullmatch(line)
        if match is None:
            raise ValueError("checksum input is malformed")
        digest, name = match.groups()
        if name in checksums:
            raise ValueError(f"duplicate checksum entry: {name}")
        checksums[name] = digest
    if set(checksums) != set(PAYLOADS):
        raise ValueError("checksum input does not contain the exact standalone payload set")
    return checksums


def generate(
    checksums: dict[str, str], tag: str, commit: str, repository: str, workflow_run: str
) -> dict[str, object]:
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", tag):
        raise ValueError("tag is not v-prefixed SemVer")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("commit must be a full lowercase Git SHA")
    if not repository or not workflow_run.startswith("https://github.com/"):
        raise ValueError("repository and GitHub workflow run are required")

    artifacts = []
    for name in sorted(PAYLOADS):
        artifact: dict[str, str] = {"name": name, "sha256": checksums[name]}
        if PAYLOADS[name] is not None:
            artifact["sbom"] = PAYLOADS[name]  # type: ignore[assignment]
        artifacts.append(artifact)

    return {
        "schemaVersion": 1,
        "scope": "standalone-linux",
        "source": {
            "repository": repository,
            "tag": tag,
            "commit": commit,
            "workflowRun": workflow_run,
        },
        "artifacts": artifacts,
        "attestation": {
            "provider": "github-artifact-attestations",
            "workflow": f"{repository}/.github/workflows/release.yml",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--workflow-run", required=True)
    args = parser.parse_args()

    directory = args.directory.resolve(strict=True)
    manifest = generate(
        read_checksums(directory / "SHA256SUMS.txt"),
        args.tag,
        args.commit,
        args.repository,
        args.workflow_run,
    )
    output = directory / "authos-standalone-release-manifest.json"
    output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
