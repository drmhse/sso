#!/usr/bin/env python3
"""Bounded, dependency-free AuthOS HTTP capacity qualification harness.

This runner intentionally reports measurements without declaring pass/fail SLOs.
Secrets and response bodies are never written to result artifacts.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import hashlib
import json
import math
import os
import platform
import re
import statistics
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
REQUIRED_CATEGORIES = {"authentication", "token", "organization", "saml", "scim"}
MAX_CONCURRENCY = 64
MAX_REQUESTS_PER_WORKLOAD = 100_000
MAX_TIMEOUT_SECONDS = 30.0
MAX_WARMUP_REQUESTS = 10_000
MAX_WORKLOADS = 32
MAX_TOTAL_REQUESTS = 100_000
MAX_ESTIMATED_SECONDS = 3_600.0
ALLOWED_SCENARIO_KEYS = {
    "name",
    "category",
    "method",
    "path",
    "requests",
    "concurrency",
    "warmup_requests",
    "timeout_seconds",
    "expected_statuses",
    "headers",
    "header_env",
    "body_env",
}
SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "proxy-authorization",
    "x-api-key",
    "api-key",
    "x-auth-token",
    "x-scim-token",
}
FORBIDDEN_REQUEST_HEADERS = {
    "connection",
    "content-length",
    "forwarded",
    "host",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "via",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


@dataclass(frozen=True)
class Workload:
    name: str
    category: str
    method: str
    path: str
    requests: int
    concurrency: int
    warmup_requests: int
    timeout_seconds: float
    expected_statuses: tuple[int, ...]
    headers: dict[str, str]
    header_env: dict[str, str]
    body_env: str | None


def parse_scenarios(document: object) -> list[Workload]:
    require(isinstance(document, dict), "scenario document must be an object")
    require(set(document) <= {"version", "workloads"}, "scenario has unknown top-level keys")
    require(document.get("version") == SCHEMA_VERSION, "scenario version must be 1")
    rows = document.get("workloads")
    require(isinstance(rows, list) and bool(rows), "scenario needs workloads")
    require(len(rows) <= MAX_WORKLOADS, f"scenario exceeds {MAX_WORKLOADS} workloads")
    workloads: list[Workload] = []
    names: set[str] = set()
    for row in rows:
        require(isinstance(row, dict), "workload must be an object")
        require(set(row) <= ALLOWED_SCENARIO_KEYS, "workload has unknown keys")
        name = row.get("name")
        category = row.get("category")
        require(
            isinstance(name, str) and bool(name) and name not in names and len(name) <= 100,
            "workload names must be non-empty, unique, and at most 100 characters",
        )
        require(category in REQUIRED_CATEGORIES, f"invalid category for {name}")
        names.add(name)
        requests = row.get("requests", 100)
        concurrency = row.get("concurrency", 1)
        warmup = row.get("warmup_requests", 0)
        timeout = float(row.get("timeout_seconds", 10))
        require(
            isinstance(requests, int)
            and not isinstance(requests, bool)
            and 1 <= requests <= MAX_REQUESTS_PER_WORKLOAD,
            f"invalid request count for {name}",
        )
        require(
            isinstance(concurrency, int)
            and not isinstance(concurrency, bool)
            and 1 <= concurrency <= MAX_CONCURRENCY,
            f"invalid concurrency for {name}",
        )
        require(
            isinstance(warmup, int)
            and not isinstance(warmup, bool)
            and 0 <= warmup <= MAX_WARMUP_REQUESTS,
            f"invalid warmup count for {name}",
        )
        require(0 < timeout <= MAX_TIMEOUT_SECONDS, f"invalid timeout for {name}")
        method = row.get("method", "GET")
        path_value = row.get("path")
        statuses = row.get("expected_statuses", [200])
        require(
            method in {"GET", "POST", "PUT", "PATCH", "DELETE"},
            f"invalid method for {name}",
        )
        require(
            isinstance(path_value, str)
            and path_value.startswith("/")
            and not path_value.startswith("//")
            and len(path_value) <= 2_048,
            f"invalid relative path for {name}",
        )
        parsed_path = urllib.parse.urlsplit(path_value)
        require(
            not parsed_path.scheme and not parsed_path.netloc and not parsed_path.fragment,
            f"path for {name} must remain a fragment-free relative URL",
        )
        sensitive_query_names = {
            key.lower()
            for key, _value in urllib.parse.parse_qsl(parsed_path.query, keep_blank_values=True)
            if any(
                marker in key.lower()
                for marker in (
                    "authorization",
                    "cookie",
                    "key",
                    "password",
                    "secret",
                    "token",
                )
            )
        }
        require(
            not sensitive_query_names,
            f"sensitive query parameter names are forbidden for {name}",
        )
        require(
            isinstance(statuses, list)
            and bool(statuses)
            and all(
                isinstance(status, int)
                and not isinstance(status, bool)
                and 100 <= status <= 599
                and not 300 <= status <= 399
                for status in statuses
            ),
            f"invalid expected statuses for {name}",
        )
        headers = row.get("headers", {})
        header_env = row.get("header_env", {})
        require(
            isinstance(headers, dict)
            and all(isinstance(key, str) and isinstance(value, str) for key, value in headers.items()),
            f"invalid literal headers for {name}",
        )
        require(
            isinstance(header_env, dict)
            and all(isinstance(key, str) and isinstance(value, str) for key, value in header_env.items()),
            f"invalid environment headers for {name}",
        )
        all_header_names = set(headers) | set(header_env)
        require(
            all(
                re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key) is not None
                for key in all_header_names
            ),
            f"invalid header name for {name}",
        )
        normalized_header_names = {key.lower() for key in all_header_names}
        require(
            not (normalized_header_names & FORBIDDEN_REQUEST_HEADERS)
            and not any(key.startswith("x-forwarded-") for key in normalized_header_names),
            f"routing or hop-by-hop headers are forbidden for {name}",
        )
        require(
            all("\r" not in value and "\n" not in value for value in headers.values()),
            f"literal header values contain control characters for {name}",
        )
        require(
            not ({key.lower() for key in headers} & SENSITIVE_HEADERS),
            f"sensitive headers for {name} must come from header_env",
        )
        body_env = row.get("body_env")
        require(
            body_env is None or (isinstance(body_env, str) and bool(body_env)),
            f"invalid body_env for {name}",
        )
        workloads.append(
            Workload(
                name=name,
                category=category,
                method=method,
                path=path_value,
                requests=requests,
                concurrency=concurrency,
                warmup_requests=warmup,
                timeout_seconds=timeout,
                expected_statuses=tuple(statuses),
                headers=headers,
                header_env=header_env,
                body_env=body_env,
            )
        )
    missing = REQUIRED_CATEGORIES - {workload.category for workload in workloads}
    require(not missing, f"scenario omits required workload categories: {sorted(missing)}")
    total_requests = sum(row.requests + row.warmup_requests for row in workloads)
    require(
        total_requests <= MAX_TOTAL_REQUESTS,
        f"scenario exceeds {MAX_TOTAL_REQUESTS} total requests",
    )
    estimated_seconds = sum(
        (
            math.ceil(row.warmup_requests / row.concurrency)
            + math.ceil(row.requests / row.concurrency)
        )
        * row.timeout_seconds
        for row in workloads
    )
    require(
        estimated_seconds <= MAX_ESTIMATED_SECONDS,
        f"worst-case scenario duration exceeds {MAX_ESTIMATED_SECONDS:g} seconds",
    )
    return workloads


def load_scenarios(path: Path) -> list[Workload]:
    return parse_scenarios(json.loads(path.read_text(encoding="utf-8")))


def validate_base_url(base_url: str, allowed_hosts: set[str]) -> str:
    parsed = urllib.parse.urlsplit(base_url)
    require(parsed.scheme in {"http", "https"}, "base URL scheme must be http or https")
    require(bool(parsed.hostname), "base URL must include a hostname")
    require(
        parsed.username is None and parsed.password is None,
        "base URL must not contain credentials",
    )
    require(
        parsed.path in {"", "/"} and not parsed.query and not parsed.fragment,
        "base URL must not contain a path, query, or fragment",
    )
    host = parsed.hostname.lower()
    loopback = host in {"localhost", "127.0.0.1", "::1"}
    require(
        loopback or host in allowed_hosts,
        f"target host {host!r} is not loopback or explicitly allowed",
    )
    return base_url.rstrip("/")


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: Any,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


# Do not inherit HTTP(S)_PROXY. An explicit target authorization must describe
# the network endpoint that receives the request, not merely a proxy request URL.
NO_REDIRECT_OPENER = urllib.request.build_opener(
    urllib.request.ProxyHandler({}), NoRedirectHandler
)


def resolve_request(workload: Workload) -> tuple[dict[str, str], bytes | None]:
    headers = dict(workload.headers)
    for header, environment_name in workload.header_env.items():
        value = os.environ.get(environment_name)
        if value is None:
            raise ValueError(f"{workload.name} requires environment variable {environment_name}")
        if "\r" in value or "\n" in value:
            raise ValueError(f"{workload.name} environment header contains control characters")
        headers[header] = value
    body = None
    if workload.body_env:
        value = os.environ.get(workload.body_env)
        if value is None:
            raise ValueError(f"{workload.name} requires environment variable {workload.body_env}")
        body = value.encode("utf-8")
    return headers, body


def one_request(base_url: str, workload: Workload, sequence: int) -> dict[str, Any]:
    headers, body = resolve_request(workload)
    request = urllib.request.Request(
        base_url.rstrip("/") + workload.path,
        data=body,
        headers=headers,
        method=workload.method,
    )
    started = time.perf_counter()
    status: int | None = None
    error_code: str | None = None
    try:
        with NO_REDIRECT_OPENER.open(request, timeout=workload.timeout_seconds) as response:
            status = response.status
            response.read(1)
    except urllib.error.HTTPError as error:
        status = error.code
        error.close()
    except urllib.error.URLError:
        error_code = "transport_error"
    except TimeoutError:
        error_code = "timeout"
    elapsed_ms = (time.perf_counter() - started) * 1000
    expected = status in workload.expected_statuses and not (
        status is not None and 300 <= status <= 399
    )
    if not expected and error_code is None:
        error_code = "unexpected_http_status"
    return {
        "schema_version": SCHEMA_VERSION,
        "workload": workload.name,
        "category": workload.category,
        "sequence": sequence,
        "duration_ms": round(elapsed_ms, 3),
        "status": status,
        "success": expected,
        "error_code": error_code,
    }


def percentile(values: list[float], percentile_value: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, math.ceil(percentile_value * len(ordered)) - 1)
    return round(ordered[index], 3)


def run_workload(base_url: str, workload: Workload) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if workload.warmup_requests:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workload.concurrency) as executor:
            list(
                executor.map(
                    lambda sequence: one_request(base_url, workload, -sequence - 1),
                    range(workload.warmup_requests),
                )
            )
    started = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=workload.concurrency) as executor:
        rows = list(
            executor.map(
                lambda sequence: one_request(base_url, workload, sequence),
                range(workload.requests),
            )
        )
    elapsed = time.perf_counter() - started
    durations = [float(row["duration_ms"]) for row in rows]
    successes = sum(bool(row["success"]) for row in rows)
    summary = {
        "name": workload.name,
        "category": workload.category,
        "requests": len(rows),
        "successes": successes,
        "errors": len(rows) - successes,
        "error_rate": round((len(rows) - successes) / len(rows), 6),
        "elapsed_seconds": round(elapsed, 6),
        "throughput_requests_per_second": round(len(rows) / elapsed, 3) if elapsed else None,
        "latency_ms": {
            "min": round(min(durations), 3),
            "mean": round(statistics.fmean(durations), 3),
            "p50": percentile(durations, 0.50),
            "p95": percentile(durations, 0.95),
            "p99": percentile(durations, 0.99),
            "max": round(max(durations), 3),
        },
    }
    return rows, summary


def host_memory_bytes() -> int | None:
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("MemTotal:"):
                return int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        return None
    return None


def write_results(
    output: Path,
    rows: list[dict[str, Any]],
    summaries: list[dict[str, Any]],
    args: argparse.Namespace,
) -> tuple[Path, Path]:
    output.mkdir(parents=True, exist_ok=True)
    raw_path = output / "capacity-raw-v1.jsonl"
    summary_path = output / "capacity-summary-v1.json"
    if raw_path.exists() or summary_path.exists():
        raise FileExistsError("output directory already contains capacity result files")
    with raw_path.open("x", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
    raw_sha256 = hashlib.sha256(raw_path.read_bytes()).hexdigest()
    result = {
        "schema_version": SCHEMA_VERSION,
        "kind": "authos-capacity-summary",
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "release": args.release,
        "topology": args.topology,
        "database": args.database,
        "scenario_sha256": args.scenario_sha256,
        "selected_configuration_sha256": args.selected_configuration_sha256,
        "environment": {
            "system": platform.system(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "logical_cpus": os.cpu_count(),
            "memory_bytes": host_memory_bytes(),
        },
        "methodology": {
            "measurement": "client-observed wall-clock HTTP latency",
            "response_body_capture": False,
            "warmup_excluded": True,
            "thresholds_applied": False,
        },
        "raw_results": {"path": raw_path.name, "sha256": raw_sha256, "rows": len(rows)},
        "workloads": summaries,
    }
    with summary_path.open("x", encoding="utf-8") as handle:
        handle.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return raw_path, summary_path


def normalized_workloads_sha256(workloads: list[Workload]) -> str:
    encoded = json.dumps(
        [dataclasses.asdict(workload) for workload in workloads],
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def ensure_output_available(output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    for name in ("capacity-raw-v1.jsonl", "capacity-summary-v1.json"):
        if (output / name).exists() or (output / name).is_symlink():
            raise FileExistsError("output directory already contains capacity result files")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenarios", type=Path, required=True)
    parser.add_argument("--base-url")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--release", default="unrecorded")
    parser.add_argument("--topology", default="unrecorded")
    parser.add_argument("--database", default="unrecorded")
    parser.add_argument("--workload", action="append", default=[])
    parser.add_argument(
        "--allow-host",
        action="append",
        default=[],
        help="exact non-loopback hostname allowed as a target; repeat as needed",
    )
    parser.add_argument("--validate-only", action="store_true")
    args = parser.parse_args()
    scenario_snapshot = args.scenarios.read_bytes()
    workloads = parse_scenarios(json.loads(scenario_snapshot.decode("utf-8")))
    selected = set(args.workload)
    if selected:
        unknown = selected - {workload.name for workload in workloads}
        if unknown:
            raise SystemExit(f"unknown workload(s): {sorted(unknown)}")
        workloads = [workload for workload in workloads if workload.name in selected]
    if args.validate_only:
        print(f"Capacity scenarios passed: {len(workloads)} selected workloads; no run executed.")
        return
    if not args.base_url or not args.output:
        raise SystemExit("--base-url and --output are required unless --validate-only is used")
    allowed_hosts = {host.lower() for host in args.allow_host}
    base_url = validate_base_url(args.base_url, allowed_hosts)
    ensure_output_available(args.output)
    args.scenario_sha256 = hashlib.sha256(scenario_snapshot).hexdigest()
    args.selected_configuration_sha256 = normalized_workloads_sha256(workloads)
    all_rows: list[dict[str, Any]] = []
    summaries: list[dict[str, Any]] = []
    for workload in workloads:
        rows, summary = run_workload(base_url, workload)
        all_rows.extend(rows)
        summaries.append(summary)
    if args.scenarios.read_bytes() != scenario_snapshot:
        raise RuntimeError("scenario file changed during the capacity run")
    write_results(args.output, all_rows, summaries, args)
    print("Capacity run recorded without SLO claims; output paths omitted from logs.")


if __name__ == "__main__":
    main()
