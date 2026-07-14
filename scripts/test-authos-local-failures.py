#!/usr/bin/env python3
"""Tests for the opt-in local failure qualification runner."""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).with_name("authos-local-failures.py")
SPEC = importlib.util.spec_from_file_location("authos_local_failures", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def manifest_cases(command: list[str], timeout: int = 1) -> dict[str, object]:
    return {
        "version": 1,
        "cases": [
            {"id": category, "category": category, "command": command, "timeout_seconds": timeout}
            for category in sorted(MODULE.REQUIRED_CATEGORIES)
        ],
    }


class LocalFailureHarnessTests(unittest.TestCase):
    def test_repository_manifest_is_bounded_and_complete(self) -> None:
        cases = MODULE.load_manifest(Path(__file__).parents[1] / "deploy/qualification/local-failure-cases.json")
        self.assertEqual({case.category for case in cases}, MODULE.REQUIRED_CATEGORIES)
        self.assertLessEqual(sum(case.timeout_seconds for case in cases), MODULE.MAX_TOTAL_TIMEOUT_SECONDS)

    def test_malformed_unbounded_and_secret_commands_fail_closed(self) -> None:
        documents = [
            {"version": 1, "cases": []},
            manifest_cases(["sh", "-c", "true"]),
            manifest_cases(["python3", "-c", "print('x')"], MODULE.MAX_TIMEOUT_SECONDS + 1),
            manifest_cases(["python3", "--token=literal-secret"]),
            manifest_cases(["python3", "-c", "import os; os.remove('README.md')"]),
            manifest_cases(["cargo", "login", "literal-token"]),
        ]
        with tempfile.TemporaryDirectory() as directory:
            for index, document in enumerate(documents):
                path = Path(directory) / f"bad-{index}.json"
                path.write_text(json.dumps(document), encoding="utf-8")
                with self.subTest(index=index), self.assertRaises(ValueError):
                    MODULE.load_manifest(path)

    def test_execution_sanitizes_environment_and_artifacts_contain_no_output(self) -> None:
        secret = "failure-harness-super-secret"
        os.environ["FAILURE_TEST_SECRET"] = secret
        command = ["python3", "-c", "import os; print(os.getenv('FAILURE_TEST_SECRET', 'missing'))"]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps(manifest_cases(command)), encoding="utf-8")
            cases = [MODULE.FailureCase("environment", "worker", tuple(command), 2)]
            row = MODULE.execute_case(cases[0], Path(__file__).parents[1])
            self.assertTrue(row["success"])
            self.assertGreater(row["stdout"]["bytes"], 0)
            raw, summary = MODULE.write_results(
                root / "results",
                "a" * 64,
                MODULE.normalized_cases_sha256(cases),
                [row],
            )
            artifacts = raw.read_text(encoding="utf-8") + summary.read_text(encoding="utf-8")
            self.assertNotIn(secret, artifacts)
            self.assertNotIn("missing", artifacts)
            self.assertNotIn("command", artifacts)
            self.assertEqual(json.loads(summary.read_text(encoding="utf-8"))["manifest_sha256"], "a" * 64)

    def test_zero_cargo_tests_cannot_be_recorded_as_success(self) -> None:
        # The marker contract itself is deterministic and is enforced in the
        # row's success predicate by execute_case. A tiny process emulates a
        # successful cargo invocation that reports zero tests.
        zero = MODULE.FailureCase(
            "missing", "worker", ("python3", "-c", "print('running 0 tests')"), 2
        )
        with mock.patch.object(
            MODULE,
            "expected_output_marker",
            return_value=("stdout", b"test missing ... ok"),
        ):
            row = MODULE.execute_case(zero, Path(__file__).parents[1])
        self.assertEqual(row["exit_code"], 0)
        self.assertFalse(row["test_execution_verified"])
        self.assertFalse(row["success"])

    def test_timeout_kills_the_case_and_is_recorded(self) -> None:
        case = MODULE.FailureCase("timeout", "worker", ("python3", "-c", "import time; time.sleep(5)"), 1)
        row = MODULE.execute_case(case, Path(__file__).parents[1])
        self.assertTrue(row["timed_out"])
        self.assertFalse(row["success"])
        self.assertLess(row["duration_seconds"], 3)

    def test_successful_parent_cannot_leave_a_pipe_holding_process_group(self) -> None:
        source = (
            "import subprocess,sys; "
            "subprocess.Popen([sys.executable,'-c','import time; time.sleep(20)'])"
        )
        case = MODULE.FailureCase("residual", "worker", ("python3", "-c", source), 5)
        row = MODULE.execute_case(case, Path(__file__).parents[1])
        self.assertTrue(row["residual_processes_terminated"])
        self.assertTrue(row["cleanup_complete"])
        self.assertFalse(row["success"])
        self.assertLess(row["duration_seconds"], 4)


if __name__ == "__main__":
    unittest.main()
