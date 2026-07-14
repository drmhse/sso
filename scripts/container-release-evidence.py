#!/usr/bin/env python3
"""Generate and verify a release-attached AuthOS container digest record."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys


BACKENDS = {"sqlite", "postgres", "mysql"}


def record(backend: str, digest: str, tag: str, commit: str, workflow_run: str) -> dict[str, object]:
    if backend not in BACKENDS:
        raise ValueError("container backend is invalid")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise ValueError("container digest is invalid")
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", tag):
        raise ValueError("container tag is invalid")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("container source commit is invalid")
    if not workflow_run.startswith("https://github.com/drmhse/AuthOS/actions/runs/"):
        raise ValueError("container workflow run is invalid")
    return {
        "schemaVersion": 1,
        "scope": "container-image",
        "backend": backend,
        "image": "docker.io/editoredit/sso",
        "tag": f"{backend if backend != 'postgres' else 'psql'}-{tag}",
        "digest": digest,
        "source": {
            "repository": "drmhse/AuthOS",
            "tag": tag,
            "commit": commit,
            "workflowRun": workflow_run,
        },
        "evidence": {
            "registryAttachments": ["application/spdx+json", "application/vnd.in-toto+json"],
            "githubProvenanceAttestation": True,
        },
    }


def verify(value: object) -> None:
    if not isinstance(value, dict) or value.get("schemaVersion") != 1 or value.get("scope") != "container-image":
        raise ValueError("container evidence schema is invalid")
    expected = record(
        str(value.get("backend", "")),
        str(value.get("digest", "")),
        str(value.get("source", {}).get("tag", "")) if isinstance(value.get("source"), dict) else "",
        str(value.get("source", {}).get("commit", "")) if isinstance(value.get("source"), dict) else "",
        str(value.get("source", {}).get("workflowRun", "")) if isinstance(value.get("source"), dict) else "",
    )
    if value != expected:
        raise ValueError("container evidence fields are inconsistent")


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    generate = subparsers.add_parser("generate")
    generate.add_argument("--backend", required=True)
    generate.add_argument("--digest", required=True)
    generate.add_argument("--tag", required=True)
    generate.add_argument("--commit", required=True)
    generate.add_argument("--workflow-run", required=True)
    generate.add_argument("--output", required=True, type=Path)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("record", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "generate":
            value = record(args.backend, args.digest, args.tag, args.commit, args.workflow_run)
            args.output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        else:
            verify(json.loads(args.record.read_text(encoding="utf-8")))
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"AuthOS container evidence failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
