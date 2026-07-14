#!/usr/bin/env python3
"""Regression tests for deterministic monitoring schema/import validation."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

MODULE_PATH = Path(__file__).with_name("check-monitoring-assets.py")
SPEC = importlib.util.spec_from_file_location("monitoring_check", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class MonitoringAssetTests(unittest.TestCase):
    def test_repository_assets_match_schema_and_source_metrics(self) -> None:
        result = MODULE.validate_assets()
        self.assertGreaterEqual(result["rules"], 1)
        self.assertGreaterEqual(result["alerts"], 1)
        self.assertGreaterEqual(result["panels"], 1)

    def test_dashboard_schema_rejects_duplicate_panel_ids(self) -> None:
        dashboard = json.loads(MODULE.DASHBOARD.read_text(encoding="utf-8"))
        dashboard["panels"][1]["id"] = dashboard["panels"][0]["id"]
        with self.assertRaisesRegex(ValueError, "panel ids must be unique"):
            MODULE.validate_dashboard(dashboard)

    def test_rules_reject_missing_runbook_anchor(self) -> None:
        rules = MODULE.RULES.read_text(encoding="utf-8").replace(
            "#alert-response", "#not-a-real-heading"
        )
        with self.assertRaisesRegex(ValueError, "runbook anchor"):
            MODULE.validate_rules(rules, MODULE.RUNBOOK.read_text(encoding="utf-8"))

    def test_native_import_failure_is_propagated(self) -> None:
        completed = mock.Mock(returncode=1, stdout="", stderr="bad rule")
        with mock.patch.object(MODULE.subprocess, "run", return_value=completed):
            with self.assertRaisesRegex(ValueError, "promtool rejected"):
                MODULE.run_promtool("promtool")

    def test_native_import_invocation_is_bounded_and_exact(self) -> None:
        completed = mock.Mock(returncode=0, stdout="SUCCESS", stderr="")
        with tempfile.TemporaryDirectory() as directory:
            rules = Path(directory) / "rules.yml"
            rules.write_text("groups: []\n", encoding="utf-8")
            with mock.patch.object(MODULE.subprocess, "run", return_value=completed) as run:
                MODULE.run_promtool("/usr/bin/promtool", rules)
        run.assert_called_once_with(
            ["/usr/bin/promtool", "check", "rules", str(rules)],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )


if __name__ == "__main__":
    unittest.main()
