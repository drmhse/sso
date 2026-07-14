#!/usr/bin/env python3
"""Deterministic schema/source checks for the starter monitoring assets.

The default check is dependency-free. If ``promtool`` is installed (or passed
with ``--promtool``), the exact rule file is also parsed by Prometheus' native
rule importer. A missing promtool is reported as an unrun live-import check,
not silently represented as operational evidence.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "deploy/monitoring/prometheus-rules.yml"
DASHBOARD = ROOT / "deploy/monitoring/grafana-dashboard.json"
RUNBOOK = ROOT / "docs/operations/monitoring.md"
SOURCE_METRIC = re.compile(r"\bsso_[a-zA-Z0-9_:]+")
RECORDING_METRIC = re.compile(r"\bauthos:[a-zA-Z0-9_:]+")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def source_metrics(root: Path = ROOT) -> set[str]:
    names: set[str] = set()
    for path in (root / "api/src").rglob("*.rs"):
        names.update(SOURCE_METRIC.findall(path.read_text(encoding="utf-8")))
    return names


def validate_rules(rule_text: str, runbook_text: str) -> tuple[list[str], list[str]]:
    require(bool(re.search(r"^groups:\s*$", rule_text, re.MULTILINE)), "rules must have groups")
    groups = re.findall(r"^  - name:\s*(\S+)\s*$", rule_text, re.MULTILINE)
    require(bool(groups) and len(groups) == len(set(groups)), "rule group names must be unique")
    require(
        all(re.fullmatch(r"[a-z0-9][a-z0-9-]*", group) for group in groups),
        "rule group names must be stable lowercase identifiers",
    )
    rule_names = re.findall(
        r"^\s+- (?:record|alert):\s*(\S+)\s*$", rule_text, re.MULTILINE
    )
    expressions = re.findall(r"^\s+expr:\s*(.+)\s*$", rule_text, re.MULTILINE)
    require(bool(rule_names) and len(rule_names) == len(expressions), "every rule needs an expression")
    require(len(rule_names) == len(set(rule_names)), "recording and alert names must be unique")
    alert_blocks = re.findall(
        r"^\s+- alert:.*?(?=^\s+- (?:alert|record):|\Z)",
        rule_text,
        re.MULTILINE | re.DOTALL,
    )
    require(bool(alert_blocks), "rules must include alerts")
    for block in alert_blocks:
        require(
            bool(re.search(r"^\s+for:\s*\d+(?:s|m|h|d)\s*$", block, re.MULTILINE)),
            "alerts need a bounded hold duration",
        )
        severity = re.search(r"^\s+severity:\s*(\S+)\s*$", block, re.MULTILINE)
        require(
            bool(severity) and severity.group(1) in {"warning", "critical"},
            "alerts need a warning or critical severity",
        )
        runbook = re.search(r"runbook_url:\s+(https://\S+)", block)
        require(bool(runbook), "alerts need a deploy-accessible HTTPS runbook")
        anchor = runbook.group(1).rsplit("#", 1)[-1]
        headings = {
            re.sub(r"[^a-z0-9 -]", "", heading.lower()).replace(" ", "-")
            for heading in re.findall(r"^##+\s+(.+)$", runbook_text, re.MULTILINE)
        }
        require(anchor in headings, f"runbook anchor does not exist: {anchor}")
    require('status="5xx"' in rule_text, "HTTP error rule must use the emitted status label")
    require("absent(up{" in rule_text, "target alert must cover missing discovery series")
    require(
        'status="pending"' in rule_text and 'status="processing"' in rule_text,
        "job alerts must cover pending and processing states",
    )
    return rule_names, expressions


def validate_dashboard(dashboard: object) -> tuple[list[dict], list[str]]:
    require(isinstance(dashboard, dict), "dashboard must be a JSON object")
    require(isinstance(dashboard.get("uid"), str) and bool(dashboard["uid"]), "dashboard needs a uid")
    require(isinstance(dashboard.get("title"), str) and bool(dashboard["title"]), "dashboard needs a title")
    require(isinstance(dashboard.get("schemaVersion"), int), "dashboard needs schemaVersion")
    require(isinstance(dashboard.get("version"), int), "dashboard needs an integer version")
    panels = dashboard.get("panels")
    require(isinstance(panels, list) and bool(panels), "dashboard needs panels")
    ids = [panel.get("id") for panel in panels if isinstance(panel, dict)]
    require(len(ids) == len(panels) and all(isinstance(value, int) for value in ids), "every panel needs an integer id")
    require(len(ids) == len(set(ids)), "panel ids must be unique")
    expressions: list[str] = []
    for panel in panels:
        require(isinstance(panel.get("title"), str) and bool(panel["title"]), "panel needs a title")
        grid = panel.get("gridPos")
        require(
            isinstance(grid, dict)
            and all(isinstance(grid.get(field), int) and grid[field] >= 0 for field in ("h", "w", "x", "y")),
            "dashboard panels need a non-negative integer gridPos",
        )
        targets = panel.get("targets")
        require(isinstance(targets, list) and bool(targets), "dashboard panels need queries")
        ref_ids = [target.get("refId") for target in targets]
        require(all(isinstance(ref_id, str) and bool(ref_id) for ref_id in ref_ids), "dashboard targets need refId")
        require(len(ref_ids) == len(set(ref_ids)), "target refIds must be unique per panel")
        for target in targets:
            expression = target.get("expr")
            require(isinstance(expression, str) and bool(expression.strip()), "dashboard targets need non-empty expressions")
            expressions.append(expression)
    return panels, expressions


def validate_assets(root: Path = ROOT) -> dict[str, int | bool]:
    rules_path = root / "deploy/monitoring/prometheus-rules.yml"
    dashboard_path = root / "deploy/monitoring/grafana-dashboard.json"
    runbook_path = root / "docs/operations/monitoring.md"
    rule_text = rules_path.read_text(encoding="utf-8")
    runbook_text = runbook_path.read_text(encoding="utf-8")
    rule_names, expressions = validate_rules(rule_text, runbook_text)
    dashboard = json.loads(dashboard_path.read_text(encoding="utf-8"))
    panels, dashboard_expressions = validate_dashboard(dashboard)
    expressions.extend(dashboard_expressions)

    available = source_metrics(root)
    referenced_source = set().union(
        *(set(SOURCE_METRIC.findall(expression)) for expression in expressions)
    )
    missing = sorted(
        metric
        for metric in referenced_source
        if metric not in available
        and not any(
            metric == f"{base}_{suffix}"
            for base in available
            for suffix in ("bucket", "count", "sum")
        )
    )
    require(not missing, f"monitoring references unknown source metrics: {missing}")
    recordings = set(re.findall(r"^\s+- record:\s*(\S+)\s*$", rule_text, re.MULTILINE))
    referenced_recordings = set().union(
        *(set(RECORDING_METRIC.findall(expression)) for expression in dashboard_expressions)
    )
    require(
        referenced_recordings <= recordings,
        "dashboard references undefined recording rules: "
        f"{sorted(referenced_recordings - recordings)}",
    )
    return {
        "rules": len(rule_names),
        "alerts": len(re.findall(r"^\s+- alert:", rule_text, re.MULTILINE)),
        "panels": len(panels),
        "native_import_checked": False,
    }


def run_promtool(promtool: str, rules_path: Path = RULES) -> None:
    completed = subprocess.run(
        [promtool, "check", "rules", str(rules_path)],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    require(
        completed.returncode == 0,
        "promtool rejected rules:\n" + completed.stdout + completed.stderr,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--promtool", help="path to native promtool importer")
    parser.add_argument(
        "--require-native-import",
        action="store_true",
        help="fail instead of reporting native import as unrun",
    )
    args = parser.parse_args()
    result = validate_assets()
    promtool = args.promtool or shutil.which("promtool")
    if promtool:
        run_promtool(promtool)
        result["native_import_checked"] = True
    elif args.require_native_import:
        raise SystemExit("promtool is required for this qualification run")

    print(
        "Monitoring assets passed: "
        f"{result['rules']} rules, {result['alerts']} alerts, {result['panels']} panels; "
        f"native_import_checked={str(result['native_import_checked']).lower()}."
    )


if __name__ == "__main__":
    main()
