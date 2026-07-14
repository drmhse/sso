# Backup and restore

AuthOS has no published backup automation, point-in-time recovery guarantee,
RPO, or RTO. The procedures below match the repository's current storage
layout and database containers, but they have not yet been certified by a
published end-to-end restore drill.

## What a recoverable backup must contain

A database dump or SQLite file alone is not a complete AuthOS backup. Retain,
encrypt, and access-control all of the following together:

- the database;
- the JWT signing key pair and key ID;
- `ENCRYPTION_KEY` and `DEVICE_TRUST_SECRET`;
- AuthOS configuration and integration credentials;
- the exact AuthOS release version and artifact digest;
- external proxy/TLS configuration when AuthOS does not manage it.

For a default standalone install, `/var/lib/authos/state.json` contains the JWT
and encryption material, `/var/lib/authos/config.json` contains managed
configuration, `/var/lib/authos/data/authos.db` is the SQLite database, and
`/etc/authos` contains install state plus the rendered environment. A custom
`standalone.dataDir` moves the managed files to that directory; read
`/etc/authos/install-state.json` before using the example below.

Backups contain authentication secrets and personal data. Store them encrypted
outside the AuthOS host, limit readers, and test deletion/retention controls.
Normal API startup rejects a missing or malformed `ENCRYPTION_KEY`, but it
cannot tell whether a well-formed key matches existing ciphertext. A restore
therefore must use the exact protected key captured with that database and must
exercise decryption-dependent journeys before it is considered successful.

## Standalone SQLite: cold backup

**Operator procedure — repository-aligned, live drill not yet published.** This
example applies only to the default `/var/lib/authos` data directory. A cold
copy avoids separating the SQLite database from its WAL state.

```bash
BACKUP_DIR=/srv/backups/authos/$(date -u +%Y%m%dT%H%M%SZ)
sudo install -d -m 0700 "${BACKUP_DIR}"
sudo systemctl stop authos.service
sudo tar --numeric-owner -C / -czf "${BACKUP_DIR}/authos-state.tar.gz" \
  var/lib/authos etc/authos
sudo sha256sum "${BACKUP_DIR}/authos-state.tar.gz" \
  | sudo tee "${BACKUP_DIR}/SHA256SUMS" >/dev/null
sudo systemctl start authos.service
curl -fsS http://127.0.0.1:3001/health/ready
```

If Caddy or a non-default port is configured, use the configured local/public
readiness URL. Record the release version returned by `/health`, the checksum,
backup location, start/end time, and whether the service restarted cleanly.

An online `sqlite3 .backup` procedure is plausible, but it is not documented as
the default until its consistency with AuthOS's WAL/checkpoint behavior has
been exercised under write load.

## Standalone SQLite: isolated restore

**Planned validation procedure — do not treat as a proven disaster-recovery
runbook yet.** Practice on an isolated host and never overwrite the only copy.

1. Verify the archive checksum and obtain the exact release that produced it.
2. Install that release with `--no-start` so the matching binary and systemd
   integration exist.
3. Stop `authos.service` and `authos-apply.path`.
4. Extract the archive at `/`, preserving its protected permissions.
5. Re-render the service environment from the restored managed state.
6. Start AuthOS and verify data and authentication journeys.

For the default data directory, steps 3–6 are:

```bash
BACKUP_DIR=/srv/backups/authos/REPLACE_WITH_BACKUP_ID
sudo sha256sum --check "${BACKUP_DIR}/SHA256SUMS"
sudo systemctl stop authos.service authos-apply.path
sudo tar --numeric-owner -C / -xzf "${BACKUP_DIR}/authos-state.tar.gz"
sudo chown -R authos:authos /var/lib/authos
sudo authos-apply apply --bundle-dir /opt/authos --skip-start --no-print-link
sudo systemctl start authos-apply.path authos.service
curl -fsS http://127.0.0.1:3001/health/ready
```

The standalone install step must use the restored release rather than
`latest`. Confirm `/health` reports the intended version. Then test at least an
existing user login, token refresh, organization access, OIDC discovery/JWKS,
and one configured enterprise or provisioning journey before accepting the
restore.

## Docker SQLite

The bootstrap-generated Compose project stores SQLite in a named volume and
secrets/configuration in its output directory (normally `.authos/`). Back up
both. Discover the actual volume name with `docker volume ls`; do not assume a
name when the Compose project was renamed.

**Operator procedure — live drill not yet published:**

```bash
docker compose -f .authos/docker-compose.yml stop authos
docker volume ls
docker run --rm \
  -v REPLACE_WITH_SQLITE_VOLUME:/source:ro \
  -v "${PWD}/backups:/backup" \
  alpine:3.20 tar -C /source -czf /backup/authos-sqlite-volume.tar.gz .
sudo tar -C . -czf backups/authos-bootstrap-state.tar.gz .authos authos.config.json
docker compose -f .authos/docker-compose.yml start authos
curl -fsS http://127.0.0.1:3001/health/ready
```

Restore into a new named volume and an isolated Compose project first. The
project has not yet committed a safe automated volume-restore command because
volume naming and storage drivers vary by operator.

## PostgreSQL and MySQL

Use the database vendor's supported physical backup or logical dump tooling,
and back up the AuthOS bootstrap output directory separately. The repository's
generated Compose services can produce logical dumps after stopping AuthOS:

```bash
docker compose -f .authos/docker-compose.yml stop authos
docker compose -f .authos/docker-compose.yml exec -T postgres \
  sh -c 'pg_dump --username="$POSTGRES_USER" --dbname="$POSTGRES_DB" --format=custom' \
  > authos-postgres.dump
docker compose -f .authos/docker-compose.yml start authos
```

```bash
docker compose -f .authos/docker-compose.yml stop authos
docker compose -f .authos/docker-compose.yml exec -T mysql \
  sh -c 'mysqldump --single-transaction --user="$MYSQL_USER" --password="$MYSQL_PASSWORD" "$MYSQL_DATABASE"' \
  > authos-mysql.sql
docker compose -f .authos/docker-compose.yml start authos
```

These examples match the generated service/environment names. They are not a
substitute for vendor-specific backup policy, managed-database snapshots, WAL
archiving/binlogs, encryption, retention, or restore testing. No AuthOS claim
is currently made for PostgreSQL PITR or MySQL point-in-time recovery.

## Restore acceptance record

A restore is evidence only when the record includes:

- AuthOS source and target versions, artifact digests, database engine/version,
  topology, and host/storage details;
- backup start/end, restore start/end, and measured data-loss window;
- checksum verification and access-control checks;
- readiness plus representative login, refresh, tenant, admin, SAML/SCIM (when
  configured), and audit/event checks;
- failures, manual interventions, and the disposition of every gap.

Only measured, repeated drills can establish RPO or RTO values.
