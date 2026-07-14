#!/usr/bin/env python3
"""Tests for the bounded capacity harness and artifact schema."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("authos-capacity.py")
SPEC = importlib.util.spec_from_file_location("authos_capacity", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"secret response body must not be captured")

    def do_POST(self) -> None:  # noqa: N802
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.do_GET()

    def log_message(self, _format: str, *_args: object) -> None:
        return


class CapacityHarnessTests(unittest.TestCase):
    def test_repository_scenarios_cover_required_categories(self) -> None:
        scenarios = MODULE.load_scenarios(
            Path(__file__).parents[1] / "deploy/qualification/capacity-scenarios.json"
        )
        self.assertEqual({row.category for row in scenarios}, MODULE.REQUIRED_CATEGORIES)

    def test_bounds_reject_unbounded_concurrency(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            path.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "workloads": [
                            {
                                "name": category,
                                "category": category,
                                "path": "/",
                                "concurrency": 65 if category == "authentication" else 1,
                            }
                            for category in MODULE.REQUIRED_CATEGORIES
                        ],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                MODULE.load_scenarios(path)

    def test_duration_bound_counts_separate_partial_warmup_and_measurement_waves(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "under-counted.json"
            path.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "workloads": [
                            {
                                "name": category,
                                "category": category,
                                "path": "/",
                                "requests": 1,
                                "warmup_requests": 1,
                                "concurrency": 64,
                                "timeout_seconds": 30,
                            }
                            for category in MODULE.REQUIRED_CATEGORIES
                        ]
                        + [
                            {
                                "name": f"extra-{index}",
                                "category": "authentication",
                                "path": "/",
                                "requests": 1,
                                "warmup_requests": 1,
                                "concurrency": 64,
                                "timeout_seconds": 30,
                            }
                            for index in range(27)
                        ],
                    }
                ),
                encoding="utf-8",
            )
            # Exact wave accounting is 32 * 2 * 30 = 1,920 seconds and remains
            # within the cap. Raising each phase to two sequential waves must fail.
            workloads = MODULE.load_scenarios(path)
            self.assertEqual(len(workloads), 32)
            document = json.loads(path.read_text(encoding="utf-8"))
            for row in document["workloads"]:
                row["requests"] = 65
                row["warmup_requests"] = 65
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "worst-case scenario duration"):
                MODULE.load_scenarios(path)

    def test_literal_sensitive_header_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            document = {
                "version": 1,
                "workloads": [
                    {
                        "name": category,
                        "category": category,
                        "path": "/",
                        "headers": {"X-Api-Key": "must-not-be-literal"}
                        if category == "authentication"
                        else {},
                    }
                    for category in MODULE.REQUIRED_CATEGORIES
                ],
            }
            path = Path(directory) / "literal-secret.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "sensitive headers"):
                MODULE.load_scenarios(path)

    def test_routing_hop_by_hop_and_malformed_headers_are_rejected(self) -> None:
        for header in ("Host", "Transfer-Encoding", "X-Forwarded-Host", "Bad Header"):
            with tempfile.TemporaryDirectory() as directory:
                document = {
                    "version": 1,
                    "workloads": [
                        {
                            "name": category,
                            "category": category,
                            "path": "/",
                            "headers": {header: "value"} if category == "authentication" else {},
                        }
                        for category in MODULE.REQUIRED_CATEGORIES
                    ],
                }
                path = Path(directory) / "unsafe-header.json"
                path.write_text(json.dumps(document), encoding="utf-8")
                with self.subTest(header=header), self.assertRaises(ValueError):
                    MODULE.load_scenarios(path)

    def test_proxy_environment_is_not_inherited(self) -> None:
        proxy_handlers = [
            handler
            for handler in MODULE.NO_REDIRECT_OPENER.handlers
            if isinstance(handler, MODULE.urllib.request.ProxyHandler)
        ]
        # urllib omits an explicitly empty ProxyHandler from the finalized
        # chain; the important invariant is that no environment-backed proxy
        # handler is present.
        self.assertEqual(proxy_handlers, [])

    def test_sensitive_query_and_expected_redirect_are_rejected(self) -> None:
        for path_value, statuses in (("/?access_token=secret", [200]), ("/callback", [302])):
            with tempfile.TemporaryDirectory() as directory:
                document = {
                    "version": 1,
                    "workloads": [
                        {
                            "name": category,
                            "category": category,
                            "path": path_value if category == "authentication" else "/",
                            "expected_statuses": statuses if category == "authentication" else [200],
                        }
                        for category in MODULE.REQUIRED_CATEGORIES
                    ],
                }
                scenario = Path(directory) / "unsafe-url.json"
                scenario.write_text(json.dumps(document), encoding="utf-8")
                with self.subTest(path=path_value, statuses=statuses), self.assertRaises(ValueError):
                    MODULE.load_scenarios(scenario)

    def test_target_safety_requires_loopback_or_exact_allowlist(self) -> None:
        self.assertEqual(
            MODULE.validate_base_url("http://127.0.0.1:8080", set()),
            "http://127.0.0.1:8080",
        )
        self.assertEqual(
            MODULE.validate_base_url("https://capacity.example", {"capacity.example"}),
            "https://capacity.example",
        )
        for url in (
            "https://capacity.example",
            "file:///tmp/result",
            "https://token@capacity.example",
            "http://127.0.0.1/admin",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                MODULE.validate_base_url(url, set())

    def test_redirect_is_not_followed(self) -> None:
        class RedirectHandler(Handler):
            followed = False

            def do_GET(self) -> None:  # noqa: N802
                if self.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", "/followed")
                    self.end_headers()
                    return
                type(self).followed = True
                super().do_GET()

        server = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        workload = MODULE.Workload(
            name="redirect",
            category="authentication",
            method="GET",
            path="/redirect",
            requests=1,
            concurrency=1,
            warmup_requests=0,
            timeout_seconds=2,
            expected_statuses=(200,),
            headers={},
            header_env={},
            body_env=None,
        )
        try:
            rows, _ = MODULE.run_workload(f"http://127.0.0.1:{server.server_port}", workload)
        finally:
            server.shutdown()
            server.server_close()
        self.assertFalse(RedirectHandler.followed)
        self.assertEqual(rows[0]["status"], 302)
        self.assertFalse(rows[0]["success"])

    def test_raw_and_summary_artifacts_are_bounded_and_secret_free(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        workload = MODULE.Workload(
            name="local",
            category="authentication",
            method="POST",
            path="/",
            requests=4,
            concurrency=2,
            warmup_requests=1,
            timeout_seconds=2,
            expected_statuses=(200,),
            headers={"Content-Type": "application/json"},
            header_env={"Authorization": "CAPACITY_TEST_AUTH"},
            body_env="CAPACITY_TEST_BODY",
        )
        secret_values = ("Bearer capacity-secret-token", '{"password":"capacity-secret"}')
        os.environ["CAPACITY_TEST_AUTH"] = secret_values[0]
        os.environ["CAPACITY_TEST_BODY"] = secret_values[1]
        try:
            rows, summary = MODULE.run_workload(
                f"http://127.0.0.1:{server.server_port}", workload
            )
        finally:
            server.shutdown()
            server.server_close()
        self.assertEqual(len(rows), 4)
        self.assertEqual(summary["successes"], 4)
        self.assertNotIn("body", json.dumps(rows))
        self.assertNotIn("secret response", json.dumps(rows))
        with tempfile.TemporaryDirectory() as directory:
            args = argparse.Namespace(
                release="test-release",
                topology="single",
                database="sqlite",
                scenario_sha256="a" * 64,
                selected_configuration_sha256=MODULE.normalized_workloads_sha256([workload]),
            )
            raw, summary_path = MODULE.write_results(
                Path(directory), rows, [summary], args
            )
            document = json.loads(summary_path.read_text(encoding="utf-8"))
            self.assertEqual(document["schema_version"], 1)
            self.assertFalse(document["methodology"]["thresholds_applied"])
            self.assertEqual(document["raw_results"]["rows"], 4)
            self.assertEqual(document["scenario_sha256"], "a" * 64)
            self.assertEqual(len(document["selected_configuration_sha256"]), 64)
            self.assertEqual(len(document["raw_results"]["sha256"]), 64)
            self.assertEqual(len(raw.read_text(encoding="utf-8").splitlines()), 4)
            artifacts = raw.read_text(encoding="utf-8") + summary_path.read_text(encoding="utf-8")
            for secret in secret_values:
                self.assertNotIn(secret, artifacts)


if __name__ == "__main__":
    unittest.main()
