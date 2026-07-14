#!/usr/bin/env python3
"""Create and verify a consistent online backup of an AuthOS SQLite database."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
from datetime import datetime, timezone
from urllib.parse import quote


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fsync_file(path: Path) -> None:
    with path.open("rb") as handle:
        os.fsync(handle.fileno())


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def create_backup(source: Path, output: Path) -> dict[str, object]:
    source = source.expanduser().resolve(strict=True)
    output = output.expanduser().resolve()
    manifest = output.with_name(f"{output.name}.manifest.json")

    if not source.is_file():
        raise ValueError(f"source is not a regular file: {source}")
    if source == output:
        raise ValueError("source and output must be different files")
    if output.exists() or manifest.exists():
        raise FileExistsError("backup output or manifest already exists")

    parent_existed = output.parent.exists()
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not parent_existed:
        os.chmod(output.parent, 0o700)
    if not output.parent.is_dir():
        raise ValueError(f"backup parent is not a directory: {output.parent}")
    old_umask = os.umask(0o077)
    lock_descriptor: int | None = None
    temporary_path: Path | None = None
    manifest_temporary_path: Path | None = None
    output_published = False

    try:
        lock_path = output.with_name(f".{output.name}.lock")
        lock_descriptor = os.open(
            lock_path,
            os.O_RDWR
            | os.O_CREAT
            | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        os.fchmod(lock_descriptor, 0o600)
        try:
            fcntl.flock(lock_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise FileExistsError("another backup is already publishing this output") from error
        # The early check is only an optimization. Recheck while holding the
        # per-output advisory lock so concurrent publishers cannot overwrite.
        if output.exists() or manifest.exists():
            raise FileExistsError("backup output or manifest already exists")

        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{output.name}.", suffix=".tmp", dir=output.parent
        )
        os.close(descriptor)
        temporary_path = Path(temporary_name)

        source_uri = f"file:{quote(str(source))}?mode=ro"
        with sqlite3.connect(source_uri, uri=True, timeout=30) as source_db:
            source_db.execute("PRAGMA busy_timeout = 30000")
            with sqlite3.connect(temporary_path) as backup_db:
                source_db.backup(backup_db, pages=256, sleep=0.05)
                integrity = backup_db.execute("PRAGMA integrity_check").fetchall()
                if integrity != [("ok",)]:
                    raise RuntimeError(f"backup integrity check failed: {integrity!r}")
                backup_db.commit()

        os.chmod(temporary_path, 0o600)
        fsync_file(temporary_path)
        record: dict[str, object] = {
            "format": "authos-sqlite-backup-v1",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "database_file": output.name,
            "sha256": sha256_file(temporary_path),
            "size_bytes": temporary_path.stat().st_size,
            "integrity_check": "ok",
        }

        manifest_fd, manifest_name = tempfile.mkstemp(
            prefix=f".{manifest.name}.", suffix=".tmp", dir=output.parent
        )
        manifest_temporary_path = Path(manifest_name)
        try:
            with os.fdopen(manifest_fd, "w", encoding="utf-8") as handle:
                json.dump(record, handle, indent=2, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(manifest_name, 0o600)
            os.replace(temporary_path, output)
            temporary_path = None
            output_published = True
            os.replace(manifest_temporary_path, manifest)
            manifest_temporary_path = None
            fsync_directory(output.parent)
        finally:
            if os.path.exists(manifest_name):
                os.unlink(manifest_name)

        return record
    finally:
        os.umask(old_umask)
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        if manifest_temporary_path is not None:
            manifest_temporary_path.unlink(missing_ok=True)
        if output_published and not manifest.exists():
            output.unlink(missing_ok=True)
            fsync_directory(output.parent)
        if lock_descriptor is not None:
            os.close(lock_descriptor)


def verify_backup(database: Path, manifest: Path) -> dict[str, object]:
    database = database.expanduser().resolve(strict=True)
    manifest = manifest.expanduser().resolve(strict=True)
    record = json.loads(manifest.read_text(encoding="utf-8"))

    if not isinstance(record, dict):
        raise ValueError("backup manifest must be a JSON object")
    if record.get("format") != "authos-sqlite-backup-v1":
        raise ValueError("unsupported backup manifest format")
    if record.get("database_file") != database.name:
        raise ValueError("manifest database filename does not match")
    if record.get("size_bytes") != database.stat().st_size:
        raise ValueError("backup size does not match manifest")
    if record.get("sha256") != sha256_file(database):
        raise ValueError("backup SHA-256 does not match manifest")

    database_uri = f"file:{quote(str(database))}?mode=ro"
    with sqlite3.connect(database_uri, uri=True, timeout=30) as restored:
        integrity = restored.execute("PRAGMA integrity_check").fetchall()
    if integrity != [("ok",)]:
        raise RuntimeError(f"backup integrity check failed: {integrity!r}")
    return record


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Create a transactionally consistent online SQLite backup and a "
            "SHA-256/integrity manifest. AuthOS keys and configuration must be "
            "backed up separately."
        )
    )
    parser.add_argument("--database", required=True, type=Path)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--output", type=Path)
    action.add_argument("--verify-manifest", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.verify_manifest is not None:
            record = verify_backup(args.database, args.verify_manifest)
        else:
            record = create_backup(args.database, args.output)
    except (json.JSONDecodeError, OSError, sqlite3.Error, RuntimeError, ValueError) as error:
        print(f"AuthOS SQLite backup failed: {error}", file=sys.stderr)
        return 1

    print(json.dumps(record, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
