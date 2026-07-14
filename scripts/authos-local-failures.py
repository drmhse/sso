#!/usr/bin/env python3
"""Validate or execute bounded repository-local failure regressions.

Execution is opt-in. Child output is never persisted; result artifacts contain
only status, duration, byte counts, and SHA-256 digests.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import re
import selectors
import signal
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = 1
MAX_CASES = 32
MAX_TIMEOUT_SECONDS = 900
MAX_TOTAL_TIMEOUT_SECONDS = 3_600
MAX_ARGUMENTS = 32
MAX_ARGUMENT_LENGTH = 512
ALLOWED_CARGO_MANIFEST = "api/Cargo.toml"
ALLOWED_PYTHON_TESTS = {
    (
        "scripts/test-authos-sqlite-backup.py",
        "SqliteBackupTests.test_manifest_failure_does_not_publish_orphan_database",
    ),
}
REQUIRED_CATEGORIES = {"database", "worker", "audit", "webhook", "storage"}
SAFE_ENVIRONMENT = {
    "PATH",
    "HOME",
    "CARGO_HOME",
    "RUSTUP_HOME",
    "TMPDIR",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


@dataclass(frozen=True)
class FailureCase:
    case_id: str
    category: str
    command: tuple[str, ...]
    timeout_seconds: int


def parse_manifest(document: object) -> list[FailureCase]:
    require(isinstance(document, dict), "failure manifest must be an object")
    require(set(document) <= {"version", "cases"}, "failure manifest has unknown keys")
    require(document.get("version") == SCHEMA_VERSION, "failure manifest version must be 1")
    rows = document.get("cases")
    require(isinstance(rows, list) and bool(rows), "failure manifest needs cases")
    require(len(rows) <= MAX_CASES, f"failure manifest exceeds {MAX_CASES} cases")
    cases: list[FailureCase] = []
    ids: set[str] = set()
    for row in rows:
        require(isinstance(row, dict), "failure case must be an object")
        require(
            set(row) == {"id", "category", "command", "timeout_seconds"},
            "failure case keys must be exact",
        )
        case_id = row["id"]
        category = row["category"]
        command = row["command"]
        timeout = row["timeout_seconds"]
        require(
            isinstance(case_id, str)
            and bool(case_id)
            and case_id not in ids
            and case_id.replace("-", "").replace("_", "").isalnum()
            and len(case_id) <= 80,
            "failure case IDs must be unique, simple, and at most 80 characters",
        )
        require(category in REQUIRED_CATEGORIES, f"invalid category for {case_id}")
        require(
            isinstance(command, list)
            and 1 <= len(command) <= MAX_ARGUMENTS
            and all(
                isinstance(arg, str) and bool(arg) and len(arg) <= MAX_ARGUMENT_LENGTH
                for arg in command
            ),
            f"invalid command for {case_id}",
        )
        is_exact_cargo_test = (
            len(command) == 7
            and command[:4] == ["cargo", "test", "--manifest-path", ALLOWED_CARGO_MANIFEST]
            and re.fullmatch(r"[A-Za-z0-9_]+(?:::[A-Za-z0-9_]+)+", command[4]) is not None
            and command[5:] == ["--", "--exact"]
        )
        is_exact_python_test = (
            len(command) == 3
            and command[0] == "python3"
            and tuple(command[1:]) in ALLOWED_PYTHON_TESTS
        )
        require(
            is_exact_cargo_test or is_exact_python_test,
            f"command does not match an approved test template for {case_id}",
        )
        require(
            all("\x00" not in arg and "\n" not in arg and "\r" not in arg for arg in command),
            f"control character in {case_id}",
        )
        require(
            not any(
                "bearer " in arg.lower()
                or "password=" in arg.lower()
                or "token=" in arg.lower()
                for arg in command
            ),
            f"possible secret literal in {case_id}",
        )
        require(
            isinstance(timeout, int)
            and not isinstance(timeout, bool)
            and 1 <= timeout <= MAX_TIMEOUT_SECONDS,
            f"invalid timeout for {case_id}",
        )
        ids.add(case_id)
        cases.append(FailureCase(case_id, category, tuple(command), timeout))
    missing = REQUIRED_CATEGORIES - {case.category for case in cases}
    require(not missing, f"failure manifest omits categories: {sorted(missing)}")
    require(
        sum(case.timeout_seconds for case in cases) <= MAX_TOTAL_TIMEOUT_SECONDS,
        "failure manifest exceeds aggregate timeout cap",
    )
    return cases


def load_manifest(path: Path) -> list[FailureCase]:
    return parse_manifest(json.loads(path.read_text(encoding="utf-8")))


def sanitized_environment() -> dict[str, str]:
    environment = {key: value for key, value in os.environ.items() if key in SAFE_ENVIRONMENT}
    environment["CARGO_TERM_COLOR"] = "never"
    environment["CARGO_NET_OFFLINE"] = "true"
    environment["NO_COLOR"] = "1"
    return environment


def expected_output_marker(case: FailureCase) -> tuple[str, bytes] | None:
    if case.command[0] == "cargo":
        return "stdout", f"test {case.command[4]} ... ok".encode("utf-8")
    if len(case.command) == 3 and tuple(case.command[1:]) in ALLOWED_PYTHON_TESTS:
        return "stderr", b"Ran 1 test"
    return None


def kill_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def execute_case(case: FailureCase, repository: Path) -> dict[str, object]:
    stdout_digest = hashlib.sha256()
    stderr_digest = hashlib.sha256()
    stdout_bytes = 0
    stderr_bytes = 0
    marker_contract = expected_output_marker(case)
    marker_found = marker_contract is None
    marker_tail = b""
    started = time.perf_counter()
    process = subprocess.Popen(
        case.command,
        cwd=repository,
        env=sanitized_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    assert process.stdout is not None and process.stderr is not None
    selector = selectors.DefaultSelector()
    for name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ, name)
    timed_out = False
    cleanup_complete = True
    residual_processes_terminated = False
    leader_exited = False
    execution_deadline = time.monotonic() + case.timeout_seconds
    cleanup_deadline: float | None = None
    try:
        while selector.get_map() or not leader_exited:
            now = time.monotonic()
            if not leader_exited:
                leader_exited = (
                    os.waitid(
                        os.P_PID,
                        process.pid,
                        os.WEXITED | os.WNOHANG | os.WNOWAIT,
                    )
                    is not None
                )
                if leader_exited:
                    cleanup_deadline = now + 2
            if not leader_exited and not timed_out and now >= execution_deadline:
                timed_out = True
                kill_process_group(process)
                cleanup_deadline = now + 5
            if cleanup_deadline is not None and now >= cleanup_deadline:
                if selector.get_map() and not residual_processes_terminated:
                    # The session leader remains unreaped here. Its PID, and
                    # therefore its process-group ID, cannot have been reused.
                    kill_process_group(process)
                    residual_processes_terminated = True
                    cleanup_deadline = now + 2
                elif selector.get_map():
                    cleanup_complete = False
                    for key in list(selector.get_map().values()):
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                elif not leader_exited:
                    raise RuntimeError("child did not exit after process-group termination")

            for key, _events in selector.select(timeout=0.02):
                try:
                    block = os.read(key.fileobj.fileno(), 65_536)
                except BlockingIOError:
                    continue
                if not block:
                    selector.unregister(key.fileobj)
                    continue
                if key.data == "stdout":
                    stdout_digest.update(block)
                    stdout_bytes += len(block)
                else:
                    stderr_digest.update(block)
                    stderr_bytes += len(block)
                if (
                    marker_contract is not None
                    and key.data == marker_contract[0]
                    and not marker_found
                ):
                    marker = marker_contract[1]
                    combined = marker_tail + block
                    marker_found = marker in combined
                    marker_tail = combined[-max(0, len(marker) - 1) :]
        exit_code = process.wait(timeout=5)
    except BaseException:
        kill_process_group(process)
        process.wait(timeout=5)
        raise
    finally:
        selector.close()
    for stream in (process.stdout, process.stderr):
        try:
            stream.close()
        except OSError:
            pass
    duration = time.perf_counter() - started
    return {
        "schema_version": SCHEMA_VERSION,
        "case_id": case.case_id,
        "category": case.category,
        "duration_seconds": round(duration, 6),
        "exit_code": exit_code,
        "timed_out": timed_out,
        "test_execution_verified": marker_found,
        "cleanup_complete": cleanup_complete,
        "residual_processes_terminated": residual_processes_terminated,
        "success": (
            exit_code == 0
            and not timed_out
            and marker_found
            and cleanup_complete
            and not residual_processes_terminated
        ),
        "stdout": {"bytes": stdout_bytes, "sha256": stdout_digest.hexdigest()},
        "stderr": {"bytes": stderr_bytes, "sha256": stderr_digest.hexdigest()},
    }


def write_results(
    output: Path,
    manifest_sha256: str,
    selected_configuration_sha256: str,
    rows: list[dict[str, object]],
) -> tuple[Path, Path]:
    output.mkdir(parents=True, exist_ok=True)
    raw_path = output / "local-failures-raw-v1.jsonl"
    summary_path = output / "local-failures-summary-v1.json"
    if raw_path.exists() or summary_path.exists():
        raise FileExistsError("output already contains local failure result files")
    with raw_path.open("x", encoding="utf-8") as handle:
        handle.write(
            "".join(
                json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"
                for row in rows
            )
        )
    summary = {
        "schema_version": SCHEMA_VERSION,
        "kind": "authos-local-failure-summary",
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "manifest_sha256": manifest_sha256,
        "selected_configuration_sha256": selected_configuration_sha256,
        "output_capture": "digests-and-byte-counts-only",
        "executed": True,
        "cases": len(rows),
        "successes": sum(bool(row["success"]) for row in rows),
        "failures": sum(not bool(row["success"]) for row in rows),
        "raw_results": {
            "path": raw_path.name,
            "sha256": hashlib.sha256(raw_path.read_bytes()).hexdigest(),
        },
    }
    with summary_path.open("x", encoding="utf-8") as handle:
        handle.write(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return raw_path, summary_path


def normalized_cases_sha256(cases: list[FailureCase]) -> str:
    encoded = json.dumps(
        [dataclasses.asdict(case) for case in cases],
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def ensure_output_available(output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    for name in ("local-failures-raw-v1.jsonl", "local-failures-summary-v1.json"):
        if (output / name).exists() or (output / name).is_symlink():
            raise FileExistsError("output already contains local failure result files")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--case", action="append", default=[])
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    manifest_snapshot = args.manifest.read_bytes()
    cases = parse_manifest(json.loads(manifest_snapshot.decode("utf-8")))
    selected_ids = set(args.case)
    if selected_ids:
        unknown = selected_ids - {case.case_id for case in cases}
        if unknown:
            raise SystemExit(f"unknown failure case(s): {sorted(unknown)}")
        cases = [case for case in cases if case.case_id in selected_ids]
    if not args.execute:
        print(f"Local failure manifest passed: {len(cases)} selected cases; no run executed.")
        return
    if args.output is None:
        raise SystemExit("--output is required with --execute")
    ensure_output_available(args.output)
    repository = Path(__file__).resolve().parents[1]
    rows = [execute_case(case, repository) for case in cases]
    if args.manifest.read_bytes() != manifest_snapshot:
        raise RuntimeError("failure manifest changed during execution")
    write_results(
        args.output,
        hashlib.sha256(manifest_snapshot).hexdigest(),
        normalized_cases_sha256(cases),
        rows,
    )
    print("Local failure run recorded; output paths omitted from logs.")
    if not all(bool(row["success"]) for row in rows):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
