# Monitoring and operational signals

AuthOS exposes health probes, Prometheus metrics, and process logs. The
repository includes a structurally checked starter Grafana dashboard and
Prometheus recording/alert rules under `deploy/monitoring/`. Their thresholds
are conservative starting points, not measured SLOs; a completed alert exercise
and production baseline are still required before relying on them.

`npm run check:monitoring` deterministically validates rule/group names, alert
metadata and runbook anchors, dashboard panel/query schema, recording-rule
references, and source metric names, with negative regression fixtures. When
`promtool` is available the same check also invokes its native rule parser; use
`python3 scripts/check-monitoring-assets.py --require-native-import` when that
native parse is mandatory. The command reports
`native_import_checked=false` instead of treating a missing tool as evidence.
Grafana API import and live query evaluation still require a real monitoring
stack.

`AuthOSPersistentProcessingOccupancy` observes only an aggregate gauge. Healthy
continuous throughput can keep that gauge nonzero even though no individual job
is stuck, so treat it as an investigation signal until AuthOS exports oldest-job
age rather than as proof of a stalled worker.

## Implemented probes

| Endpoint | Implemented meaning | What it does not prove |
| --- | --- | --- |
| `/health` | HTTP 200 with `status: healthy` and the embedded build version. | Database or dependency health. |
| `/health/live` | HTTP 200 if the Axum process can answer. | Readiness or correctness. |
| `/health/ready` | HTTP 200 after a database `SELECT 1`; HTTP 503 when that query fails. | Migrations beyond successful startup, SMTP, OAuth/SAML upstreams, webhook destinations, job progress, storage headroom, or end-to-end login. |
| `/metrics` | Prometheus text rendered only when `METRICS_BEARER_TOKEN` is configured and the request supplies the exact bearer token; otherwise HTTP 404 (disabled) or 401 (bad/missing token). | Tenant authorization, network isolation, or safe treatment of every future metric label. |

**Operator checks — repository-verified commands, live alert drill not yet
published:**

```bash
AUTHOS_URL=https://auth.example.com
METRICS_BEARER_TOKEN='read-from-your-secret-manager'
curl -fsS "${AUTHOS_URL}/health"
curl -fsS "${AUTHOS_URL}/health/live"
curl -fsS "${AUTHOS_URL}/health/ready"
curl -fsS -H "Authorization: Bearer ${METRICS_BEARER_TOKEN}" \
  "${AUTHOS_URL}/metrics" | sed -n '1,40p'
```

`/metrics` is disabled by default. Set `METRICS_BEARER_TOKEN` to at least 32
random ASCII characters to enable it; `openssl rand -hex 32` generates a suitable
value. Store the value in a secret manager and configure the scraper's
`Authorization: Bearer` header. The application stores only its SHA-256 digest
in the metrics access state and compares presented-token digests in constant
time. It never accepts the token in a query string.

The bearer check is defense in depth, not a replacement for network policy.
Restrict `/metrics` to the monitoring network or an authenticated reverse
proxy, strip client-supplied `Authorization` where the proxy injects its own,
and keep TLS enabled between any untrusted hops. Metrics can include total
users, organizations, MFA adoption, job state, and other platform-level
information. Do not expose them merely because health probes are safe to expose.

All endpoints are also subject to `MAX_REQUEST_BODY_BYTES`, a streaming body
limit that defaults to 1,048,576 bytes (1 MiB). A declared oversized body is
rejected immediately; a chunked body that crosses the bound fails as it is
consumed, producing HTTP 413 for normal body extractors. Set the proxy's body
limit to the same or a smaller value. Raise the application value only after
measuring the largest legitimate SAML, SCIM, webhook, and API payload; the
configured value applies globally and an invalid or zero value prevents startup.

## Prometheus series in the current API

The API registers or records these operational series:

- `sso_http_request_duration_seconds` labeled by HTTP method, matched route
  pattern, and status class;
- `sso_db_pool_connections_total`, `sso_db_pool_connections_idle`, and
  `sso_db_pool_connections_max` labeled by backend;
- `sso_job_queue_depth` and `sso_pending_jobs_total`;
- `sso_active_users_total`, `sso_total_organizations`,
  `sso_mfa_enabled_users_total`, and `sso_mfa_adoption_percentage`;
- authentication/token/MFA counters including `sso_login_failures_total`,
  `sso_auth_attempts_total`, `sso_auth_tokens_issued_total`, and
  `sso_mfa_challenges_total`;
- webhook, SIEM, API error/request, and job-processing metrics.

Some event-driven series are absent until the event occurs, and some registered
helpers may not yet be wired into every path. Validate actual scrape output for
the release under test before writing a query or alert. Database/user/job gauges
are refreshed by a background task approximately every 30 seconds, so they are
not transactionally current.

## Logs

The current API writes human-readable tracing output to stdout according to
`RUST_LOG`. It does not emit JSON structured logs by default. Standalone logs
normally go to journald; Compose logs use the configured Docker logging driver.

```bash
sudo journalctl -u authos.service --since '-30 minutes' --no-pager
sudo systemctl show authos.service \
  --property=ActiveState,NRestarts,ExecMainStatus
docker compose -f .authos/docker-compose.yml logs --since=30m authos
```

Restrict log access. Published releases through `v0.8.2` log the configured
database URL at startup, which can include PostgreSQL/MySQL credentials. The
current development line redacts that value to the database scheme, but this
fix is not available to operators until a patched release is published. The
development line also removes OAuth token response bodies, access-token hashes,
and registration email addresses from known log statements. The rest of the
logging surface has not completed a redaction assessment, so treat logs as
potentially sensitive and do not export them to broad-access systems.

## Signals to baseline before alerting

The following are useful candidates, but the project intentionally supplies no
unmeasured numeric thresholds:

- consecutive readiness failure and unexpected process restarts;
- 5xx rate and request-latency percentiles by matched route;
- database pool in-use pressure and acquisition errors;
- pending/processing job growth and oldest-job age (the latter is not currently
  exported as a dedicated metric);
- login failures by reason, MFA failures, and unusual token issuance volume;
- webhook/SIEM delivery failures and SMTP delivery failures (dedicated SIEM
  failure counters are defined but not yet wired to a delivery worker, so the
  starter rules intentionally do not alert on them);
- database/volume free space, inode usage, I/O latency, and SQLite WAL growth;
- backup age, checksum failure, and restore-drill age;
- TLS/certificate expiry, DNS failure, clock skew, and upstream IdP reachability.

Alert thresholds should record the topology, release, normal traffic window,
failure condition, responder, and linked runbook. An alert is not considered
operational evidence until a controlled exercise proves it fires and leads to
recovery.

## Current observability gaps

- `/metrics` has bearer-token authentication but no dedicated bind address;
- default logs are not structured, and the broader logging surface still needs
  a credential/personal-data redaction assessment;
- no trace export is documented;
- readiness does not cover migrations, job workers, SMTP, federation,
  provisioning, or storage pressure;
- the committed starter dashboard and rules have structural/source-metric
  checks and an optional native `promtool` parse, but no real Grafana import,
  live Prometheus evaluation, measured threshold baseline, or controlled
  firing/recovery exercise has been published;
- backup age, oldest job age, disk/WAL state, and dependency health need
  dedicated signals or external monitoring;
- repository-local redaction and bounded failure-harness tests do not yet have
  a published controlled alert or external failure drill. See
  [local failure qualification](./failure-qualification.md).

## Alert response

Import `deploy/monitoring/prometheus-rules.yml` into the same Prometheus rule
loader that scrapes AuthOS and import `deploy/monitoring/grafana-dashboard.json`
into Grafana. Change the `up{job=~"authos.*"}` selector if the scrape job does
not start with `authos`.

For any alert, first correlate `/health/ready`, process restart state, request
logs, database-pool utilization, and job depth over the alert window. Preserve
the release version, topology, alert expression/value, and relevant redacted
logs. Page immediately for `AuthOSUnavailable`; investigate the warning alerts
before changing thresholds. A threshold change needs a traffic baseline and a
recorded reason, not merely an attempt to silence an alert.

Exercise each alert in disposable infrastructure by creating its stated fault,
confirming notification delivery, following this response path, removing the
fault, and confirming resolution. Record timings and artifacts against the
exact release candidate; the checked templates alone are not drill evidence.
