# Supported deployment topologies

AuthOS is in the pre-1.0 series. This page describes what the repository can
deploy today; it is not an availability or support guarantee. The maturity
labels in [PROJECT_STATUS.md](../../PROJECT_STATUS.md) remain authoritative.

## Evidence status

- **Repository-verified** means the behavior is present in the current source,
  installer, or generated Compose configuration.
- **Operator check** means the command is safe and corresponds to the current
  implementation, but the project has not yet published a completed live drill.
- **Not yet verified** means no production-readiness claim should be based on it.

No topology currently has a published RPO, RTO, availability target, capacity
limit, or high-availability qualification report.

## Current topology matrix

| Topology | Repository-verified behavior | Current boundary |
| --- | --- | --- |
| Standalone SQLite on Linux | The release installer selects `linux/amd64` or `linux/arm64`, installs one systemd service, stores the database under the managed data directory, and can optionally configure local Caddy. | **Beta, single node.** Requires Linux, systemd, Python 3, OpenSSL, and the installer prerequisites in the README. It has no multi-writer, failover, or HA guarantee. |
| Docker with SQLite | The bootstrap generator creates one AuthOS container with one named data volume. | **Beta, single application replica.** Do not put the SQLite file on a shared volume or run multiple writers. Volume durability, snapshots, and host recovery are operator responsibilities. |
| Docker with PostgreSQL | A PostgreSQL-specific API image and a generated one-API/one-database Compose topology exist. `DATABASE_URL` can point the API image at a PostgreSQL service. | **Beta.** The included Compose database is a development/evaluation convenience, not an HA database design. Exact server-version and managed-service compatibility matrices are not published. |
| Docker with MySQL | A MySQL-specific API image and a generated one-API/one-database Compose topology exist. `DATABASE_URL` can point the API image at a MySQL service. | **Beta.** The included Compose database is a development/evaluation convenience, not an HA database design. Exact server-version and managed-service compatibility matrices are not published. |
| Multiple AuthOS API replicas | The API can be built for PostgreSQL or MySQL, but several background jobs, process-local caches, migrations, and rolling-upgrade behavior have not been qualified together. | **Unsupported as a general HA claim.** Do not advertise or assume safe active-active operation until the multi-node test plan is complete. |

The standalone installer deliberately rejects non-SQLite backends. PostgreSQL
and MySQL deployments use the corresponding backend-specific container or a
manually managed binary; they are not selectable in the standalone installer.

## SQLite boundary

The SQLite build enables WAL mode and uses a single-connection writer pool in
the API process. Those implementation choices reduce in-process contention;
they do not make SQLite a distributed database.

Use SQLite only when all of the following are acceptable:

- one AuthOS application node owns the database;
- the data directory is durable local storage on that node;
- maintenance and recovery can include application downtime;
- recovery depends on tested backups rather than automatic failover.

Do not use network-file-system locking, shared writable volumes, multiple
AuthOS writers, or container replica scaling with the SQLite database. Those
configurations have not been qualified.

## Network and dependency boundary

AuthOS serves plain HTTP itself. TLS is terminated by optional Caddy in the
standalone flow or by an operator-managed reverse proxy/load balancer. When a
trusted proxy supplies client-address headers, configure both
`TRUST_PROXY_HEADERS=true` and a narrow `TRUSTED_PROXY_IPS` allowlist.

Depending on enabled journeys, operators must also provide reliable DNS,
clock synchronization, SMTP, upstream OAuth/SAML identity providers, webhook
destinations, and optional GeoIP data. `/health/ready` currently checks the
database connection only; it does not prove these dependencies work.

The following endpoints are implemented:

- `/health` — process response plus build version;
- `/health/live` — process liveness only;
- `/health/ready` — process readiness plus a database `SELECT 1`;
- `/metrics` — disabled by default; Prometheus text output requires the exact
  bearer token configured through `METRICS_BEARER_TOKEN`.

Also restrict `/metrics` at the proxy or network boundary because it exposes
platform-level operational counts and has no dedicated listener. See
[monitoring.md](./monitoring.md).

## Operator checks

Set `AUTHOS_URL` to the exact public base URL:

```bash
AUTHOS_URL=https://auth.example.com
curl -fsS "${AUTHOS_URL}/health"
curl -fsS "${AUTHOS_URL}/health/live"
curl -fsS "${AUTHOS_URL}/health/ready"
curl -fsS "${AUTHOS_URL}/.well-known/openid-configuration"
curl -fsS "${AUTHOS_URL}/.well-known/jwks.json"
```

These checks confirm routing and the implemented probes. They do not establish
HA, protocol conformance, recoverability, or a production support commitment.

## Evidence still required

- clean deployment drills for every topology and published platform matrix;
- PostgreSQL and MySQL server-version/runtime compatibility results;
- resource sizing and capacity tests with reproducible environments;
- host-restart, disk-full, dependency-outage, and database-failure exercises;
- multi-replica job, cache, migration, and rolling-upgrade qualification;
- measured restore drills before publishing RPO/RTO values.
