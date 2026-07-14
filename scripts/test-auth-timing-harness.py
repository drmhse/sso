#!/usr/bin/env python3

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("auth-timing-harness.py")
SPEC = importlib.util.spec_from_file_location("auth_timing_harness", MODULE_PATH)
assert SPEC and SPEC.loader
HARNESS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HARNESS)


class AuthTimingHarnessTests(unittest.TestCase):
    def test_redirects_are_refused(self):
        self.assertIsNone(
            HARNESS.NoRedirect().redirect_request(
                None,
                None,
                302,
                "Found",
                {},
                "https://other.example.test/collect",
            )
        )

    def test_summary_is_deterministic(self):
        self.assertEqual(
            HARNESS.summarize([5.0, 1.0, 3.0, 2.0, 4.0]),
            {
                "count": 5,
                "min_ms": 1.0,
                "median_ms": 3.0,
                "p95_ms": 5.0,
                "max_ms": 5.0,
                "mad_ms": 1.0,
            },
        )

    def test_scenario_loader_rejects_host_override_and_count_overflow(self):
        invalid_documents = [
            {
                "version": 1,
                "scenarios": [{"name": "override", "path": "//other.example/path"}],
            },
            {
                "version": 1,
                "scenarios": [
                    {"name": f"scenario-{index}", "path": "/api/auth/login"}
                    for index in range(HARNESS.MAX_SCENARIOS + 1)
                ],
            },
        ]
        for document in invalid_documents:
            with self.subTest(document=document):
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "scenarios.json"
                    path.write_text(json.dumps(document), encoding="utf-8")
                    with self.assertRaises(ValueError):
                        HARNESS.load_scenarios(path)

    def test_scenario_loader_normalizes_method(self):
        document = {
            "version": 1,
            "scenarios": [
                {
                    "name": "missing-password-user",
                    "method": "post",
                    "path": "/api/auth/login",
                    "expected_statuses": [401],
                    "json": {"email": "missing@example.invalid", "password": "invalid"},
                }
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scenarios.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            scenarios = HARNESS.load_scenarios(path)
        self.assertEqual(scenarios[0]["method"], "POST")

    def test_base_url_rejects_reportable_credentials_query_and_fragment(self):
        invalid = [
            "https://user:secret@example.test/auth",
            "https://example.test/auth?token=secret",
            "https://example.test/auth#secret",
        ]
        for value in invalid:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    HARNESS.validated_base_url(value)

        self.assertEqual(
            HARNESS.validated_base_url("https://example.test/auth/"),
            "https://example.test",
        )


if __name__ == "__main__":
    unittest.main()
