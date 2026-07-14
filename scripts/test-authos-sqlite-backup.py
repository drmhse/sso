#!/usr/bin/env python3
"""Regression tests for the online AuthOS SQLite backup helper."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import unittest
from unittest import mock


SCRIPT = Path(__file__).with_name("authos-sqlite-backup.py")
SPEC = importlib.util.spec_from_file_location("authos_sqlite_backup", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class SqliteBackupTests(unittest.TestCase):
    def test_online_backup_is_coherent_during_writes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="authos-backup-test-") as temp:
            root = Path(temp)
            source = root / "source.db"
            backup = root / "backup" / "authos.db"

            with sqlite3.connect(source) as database:
                database.execute("PRAGMA journal_mode = WAL")
                database.execute(
                    "CREATE TABLE events (sequence INTEGER PRIMARY KEY, value TEXT NOT NULL)"
                )
                database.commit()

            stop = threading.Event()
            writer_errors: list[Exception] = []

            def write_rows() -> None:
                try:
                    with sqlite3.connect(source, timeout=30) as database:
                        sequence = 1
                        while not stop.is_set():
                            database.execute(
                                "INSERT INTO events(sequence, value) VALUES (?, ?)",
                                (sequence, f"event-{sequence}"),
                            )
                            database.commit()
                            sequence += 1
                except Exception as error:  # pragma: no cover - asserted below
                    writer_errors.append(error)

            writer = threading.Thread(target=write_rows, daemon=True)
            writer.start()
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                with sqlite3.connect(source) as database:
                    count = database.execute("SELECT COUNT(*) FROM events").fetchone()[0]
                if count >= 20:
                    break
                time.sleep(0.01)
            else:
                self.fail("writer did not populate the source database")

            record = MODULE.create_backup(source, backup)
            stop.set()
            writer.join(timeout=5)
            self.assertFalse(writer.is_alive())
            self.assertEqual(writer_errors, [])

            with sqlite3.connect(backup) as restored:
                count, maximum = restored.execute(
                    "SELECT COUNT(*), MAX(sequence) FROM events"
                ).fetchone()
                self.assertGreaterEqual(count, 20)
                self.assertEqual(count, maximum)
                self.assertEqual(restored.execute("PRAGMA integrity_check").fetchone(), ("ok",))

            manifest = json.loads(
                backup.with_name("authos.db.manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(manifest, record)
            self.assertEqual(manifest["format"], "authos-sqlite-backup-v1")
            self.assertEqual(manifest["integrity_check"], "ok")
            self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
            self.assertEqual(
                MODULE.verify_backup(
                    backup, backup.with_name("authos.db.manifest.json")
                ),
                record,
            )

            with backup.open("r+b") as handle:
                handle.seek(64)
                original = handle.read(1)
                handle.seek(64)
                handle.write(bytes([original[0] ^ 0xFF]))
            with self.assertRaises(ValueError):
                MODULE.verify_backup(
                    backup, backup.with_name("authos.db.manifest.json")
                )

    def test_refuses_to_overwrite_an_existing_backup(self) -> None:
        with tempfile.TemporaryDirectory(prefix="authos-backup-test-") as temp:
            root = Path(temp)
            source = root / "source.db"
            output = root / "backup.db"
            with sqlite3.connect(source) as database:
                database.execute("CREATE TABLE marker (value TEXT)")
            output.write_bytes(b"do-not-replace")

            with self.assertRaises(FileExistsError):
                MODULE.create_backup(source, output)
            self.assertEqual(output.read_bytes(), b"do-not-replace")

    def test_existing_parent_permissions_are_preserved(self) -> None:
        with tempfile.TemporaryDirectory(prefix="authos-backup-test-") as temp:
            root = Path(temp)
            source = root / "source.db"
            shared = root / "shared"
            shared.mkdir(mode=0o750)
            shared.chmod(0o750)
            with sqlite3.connect(source) as database:
                database.execute("CREATE TABLE marker (value TEXT)")

            MODULE.create_backup(source, shared / "backup.db")
            self.assertEqual(shared.stat().st_mode & 0o777, 0o750)

    def test_manifest_failure_does_not_publish_orphan_database(self) -> None:
        with tempfile.TemporaryDirectory(prefix="authos-backup-test-") as temp:
            root = Path(temp)
            source = root / "source.db"
            output = root / "backup" / "backup.db"
            with sqlite3.connect(source) as database:
                database.execute("CREATE TABLE marker (value TEXT)")

            with mock.patch.object(MODULE.json, "dump", side_effect=OSError("disk full")):
                with self.assertRaises(OSError):
                    MODULE.create_backup(source, output)

            self.assertFalse(output.exists())
            self.assertFalse(output.with_name("backup.db.manifest.json").exists())

    def test_concurrent_publishers_have_exactly_one_winner(self) -> None:
        with tempfile.TemporaryDirectory(prefix="authos-backup-test-") as temp:
            root = Path(temp)
            source = root / "source.db"
            output = root / "backup" / "backup.db"
            with sqlite3.connect(source) as database:
                database.execute("CREATE TABLE marker (value TEXT)")
                database.executemany(
                    "INSERT INTO marker(value) VALUES (?)",
                    ((f"row-{index}",) for index in range(50_000)),
                )
                database.commit()

            barrier = threading.Barrier(3)
            outcomes: list[str] = []

            def publish() -> None:
                barrier.wait()
                try:
                    MODULE.create_backup(source, output)
                    outcomes.append("success")
                except FileExistsError:
                    outcomes.append("locked")

            threads = [threading.Thread(target=publish) for _ in range(2)]
            for thread in threads:
                thread.start()
            barrier.wait()
            for thread in threads:
                thread.join(timeout=10)

            self.assertEqual(sorted(outcomes), ["locked", "success"])
            MODULE.verify_backup(output, output.with_name("backup.db.manifest.json"))


if __name__ == "__main__":
    unittest.main()
