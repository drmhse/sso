# Local failure qualification

The repository contains deterministic failure regressions and an opt-in runner
for them. These tests exercise bounded code-level failure states. They do not
replace dependency, process, host, network, or storage faults against a built
release in disposable infrastructure.

## Implemented local cases

`deploy/qualification/local-failure-cases.json` catalogs the following cases:

| Area | Local deterministic evidence | Boundary |
| --- | --- | --- |
| Database disconnect | Readiness returns unavailable after its SQLite pool is closed. | Does not exercise a real database process, proxy, DNS, or network failure. |
| Database pool exhaustion | A one-connection SQLite pool is held past a bounded acquisition timeout; readiness fails and then recovers when released. | Does not qualify production pool sizing or multi-replica exhaustion. |
| Worker retry | A queued job is rescheduled after a transient failure and becomes permanently failed at its configured attempt bound. | Does not kill a worker between claim and completion or prove multi-worker leasing. |
| Audit reconciliation | A durable enqueue survives a closed wake channel and is replayed after actor restart; a separate case reaches observable dead-letter state at its retry bound. | Does not prove PostgreSQL/MySQL outage recovery, multiple reconcilers, or operator requeue. |
| Webhook retry/reconciliation | Pending delivery polling enforces attempt bounds, active parent state, exact webhook identity, and targeted retry/permanent failure mutations. | Does not send to a failing live destination or qualify network backoff timing. |
| Safe disk-full path | The SQLite backup test injects a manifest-write `disk full` error and proves no orphan database or manifest is published. | This is an injected write failure. It does not fill a host, filesystem, database volume, or WAL volume. |

Never simulate disk full by filling the server root filesystem. Use a disposable
volume with an enforced quota for the external exercise, keep the database and
backup targets isolated, and predefine cleanup and abort thresholds.

## Runner safety and result schema

Validate the committed manifest without executing a case:

```bash
npm run check:failures
```

Execution requires an explicit flag and output directory. A single case can be
selected before running the complete catalog:

```bash
python3 scripts/authos-local-failures.py \
  --manifest deploy/qualification/local-failure-cases.json \
  --case database-disconnect-readiness \
  --execute \
  --output evidence/failures/database-disconnect
```

The runner accepts only exact `cargo test --manifest-path api/Cargo.toml ... --
--exact` and reviewed repository Python-unittest command templates; it does not
invoke a shell or permit general Cargo, npm, Python `-c`, or arbitrary script
execution. It enforces per-case and aggregate timeouts, retains the child
session leader until cleanup so its process-group ID cannot be reused, kills a
timed-out or pipe-holding residual process group, bounds output-drain cleanup,
supplies a small allowlist of non-secret environment variables, and rejects
likely secret literals in command arguments. Cargo success also requires the
exact named test's `... ok` sentinel, so a typo that runs zero tests fails.
Child stdout and stderr are consumed but never written. The versioned JSONL
result contains only the case ID/category, duration, exit status,
timeout/success/verification state, byte counts, and SHA-256 digests of the two
streams. The JSON summary binds the raw result, the snapshotted manifest, and
the normalized selected-case configuration by digest; it refuses the evidence
write if the manifest changes during execution. No command, environment value,
or child output is stored.

Result artifacts prove only the cases that are present and successful in that
exact run. A manifest validation message explicitly says that no run executed;
it is not failure-injection evidence.

## External exercises still required

Against an exact release candidate in disposable infrastructure, separately
exercise database process/network loss and pool exhaustion, worker termination
at each state transition, multiple reconcilers, webhook/SIEM/SMTP destination
failure, dependency timeouts, storage and inode exhaustion, SQLite WAL growth,
host restart, clock skew, proxy/DNS failure, and rolling deployment behavior.
Correlate every fault with readiness, metrics, logs, alerts, persisted state,
recovery actions, and post-recovery reconciliation. Redact artifacts and record
the release/topology/fault timeline before treating the exercise as evidence.
