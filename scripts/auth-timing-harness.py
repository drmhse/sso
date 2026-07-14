#!/usr/bin/env python3
"""Bounded HTTP timing sampler for authentication response-shape review.

This tool reports observations; it does not assert constant-time behavior or set
a timing pass/fail threshold. Run it only against an isolated test deployment.
"""

from __future__ import annotations

import argparse
import json
import math
import random
import statistics
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any

MAX_SCENARIOS = 20
MAX_SAMPLES = 200
MAX_WARMUPS = 20
MAX_TIMEOUT_SECONDS = 30.0
MAX_RESPONSE_BYTES = 64 * 1024
ALLOWED_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


HTTP_OPENER = urllib.request.build_opener(NoRedirect)


def percentile_nearest_rank(values: list[float], percentile: float) -> float:
    if not values:
        raise ValueError("at least one observation is required")
    ordered = sorted(values)
    rank = max(1, math.ceil((percentile / 100.0) * len(ordered)))
    return ordered[rank - 1]


def summarize(values: list[float]) -> dict[str, float | int]:
    median = statistics.median(values)
    deviations = [abs(value - median) for value in values]
    return {
        "count": len(values),
        "min_ms": round(min(values), 3),
        "median_ms": round(median, 3),
        "p95_ms": round(percentile_nearest_rank(values, 95), 3),
        "max_ms": round(max(values), 3),
        "mad_ms": round(statistics.median(deviations), 3),
    }


def load_scenarios(path: Path) -> list[dict[str, Any]]:
    raw = path.read_bytes()
    if len(raw) > 1024 * 1024:
        raise ValueError("scenario file exceeds 1 MiB")
    document = json.loads(raw)
    if not isinstance(document, dict) or document.get("version") != 1 or not isinstance(
        document.get("scenarios"), list
    ):
        raise ValueError("scenario document must contain version 1 and a scenarios array")
    scenarios = document["scenarios"]
    if not 1 <= len(scenarios) <= MAX_SCENARIOS:
        raise ValueError(f"scenario count must be between 1 and {MAX_SCENARIOS}")

    names: set[str] = set()
    for scenario in scenarios:
        if not isinstance(scenario, dict):
            raise ValueError("each scenario must be an object")
        name = scenario.get("name")
        method_value = scenario.get("method", "POST")
        path_value = scenario.get("path")
        if not isinstance(name, str) or not name or len(name) > 100 or name in names:
            raise ValueError("scenario names must be unique non-empty strings up to 100 characters")
        if not isinstance(method_value, str) or method_value.upper() not in ALLOWED_METHODS:
            raise ValueError(f"scenario {name!r} uses an unsupported method")
        method = method_value.upper()
        if not isinstance(path_value, str) or not path_value.startswith("/") or len(path_value) > 2048:
            raise ValueError(f"scenario {name!r} path must be a relative absolute-path")
        if urllib.parse.urlsplit(path_value).netloc:
            raise ValueError(f"scenario {name!r} path must not override the target host")
        expected = scenario.get("expected_statuses", [])
        if not isinstance(expected, list) or any(
            not isinstance(status, int) or not 100 <= status <= 599 for status in expected
        ):
            raise ValueError(f"scenario {name!r} expected_statuses must contain HTTP status codes")
        scenario["method"] = method
        names.add(name)
    return scenarios


def validated_base_url(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("base_url must be an http(s) URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("base_url must not contain credentials")
    if parsed.query or parsed.fragment:
        raise ValueError("base_url must not contain a query string or fragment")
    # Reports retain only the origin. A deployment path can contain internal
    # routing detail and is unnecessary for interpreting timing distributions.
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))


def sample(base_url: str, scenario: dict[str, Any], timeout: float) -> tuple[float, int]:
    url = urllib.parse.urljoin(base_url.rstrip("/") + "/", scenario["path"].lstrip("/"))
    body = None
    headers = {"Accept": "application/json"}
    if "json" in scenario:
        body = json.dumps(scenario["json"], separators=(",", ":")).encode("utf-8")
        headers["Content-Type"] = "application/json"
    started = time.perf_counter_ns()
    try:
        with HTTP_OPENER.open(
            urllib.request.Request(url, data=body, headers=headers, method=scenario["method"]),
            timeout=timeout,
        ) as response:
            response.read(MAX_RESPONSE_BYTES + 1)
            status = response.status
    except urllib.error.HTTPError as error:
        error.read(MAX_RESPONSE_BYTES + 1)
        status = error.code
    elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
    return elapsed_ms, status


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("base_url", help="isolated deployment base URL")
    parser.add_argument("scenario_file", type=Path)
    parser.add_argument("--samples", type=int, default=30)
    parser.add_argument("--warmups", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    if not 1 <= args.samples <= MAX_SAMPLES:
        parser.error(f"--samples must be between 1 and {MAX_SAMPLES}")
    if not 0 <= args.warmups <= MAX_WARMUPS:
        parser.error(f"--warmups must be between 0 and {MAX_WARMUPS}")
    if not 0 < args.timeout <= MAX_TIMEOUT_SECONDS:
        parser.error(f"--timeout must be greater than 0 and at most {MAX_TIMEOUT_SECONDS}")
    try:
        report_target = validated_base_url(args.base_url)
    except ValueError as error:
        parser.error(str(error))

    scenarios = load_scenarios(args.scenario_file)
    observations: dict[str, list[float]] = {scenario["name"]: [] for scenario in scenarios}
    statuses: dict[str, Counter[int]] = {scenario["name"]: Counter() for scenario in scenarios}
    unexpected = False

    for scenario in scenarios:
        for _ in range(args.warmups):
            sample(args.base_url, scenario, args.timeout)

    rng = random.Random(args.seed)
    for _ in range(args.samples):
        ordered = scenarios.copy()
        rng.shuffle(ordered)
        for scenario in ordered:
            elapsed_ms, status = sample(args.base_url, scenario, args.timeout)
            observations[scenario["name"]].append(elapsed_ms)
            statuses[scenario["name"]][status] += 1
            expected = scenario.get("expected_statuses", [])
            unexpected |= bool(expected and status not in expected)

    report = {
        "schema_version": 1,
        "notice": (
            "Observational timing sample only. Results do not establish constant-time behavior "
            "and must be interpreted with response-shape tests and production telemetry."
        ),
        "target": report_target,
        "samples_per_scenario": args.samples,
        "warmups_per_scenario": args.warmups,
        "seed": args.seed,
        "scenarios": [
            {
                "name": scenario["name"],
                "expected_statuses": scenario.get("expected_statuses", []),
                "statuses": {str(code): count for code, count in sorted(statuses[scenario["name"]].items())},
                "timing": summarize(observations[scenario["name"]]),
            }
            for scenario in scenarios
        ],
    }
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 2 if unexpected else 0


if __name__ == "__main__":
    raise SystemExit(main())
