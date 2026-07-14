# Upgrade and rollback

AuthOS is pre-1.0 and does not yet publish a supported source-version upgrade
matrix. Database migrations run automatically when the API starts. The current
installer and Compose bootstrap do not create a pre-upgrade backup, prove
schema backward compatibility, or automatically roll back a failed migration.

Local SQLite CI now exercises one representative pre-hardening schema origin
through the current head while preserving user, session, and webhook data and
checking the refresh-token invalidation contract. A second runner-level fixture
injects a late index failure, verifies rollback/data preservation and an
unrecorded migration, then retries successfully. The shared head-schema
assertion is reusable by PostgreSQL/MySQL CI, but no PostgreSQL/MySQL runtime or
published source-release compatibility evidence is implied by these fixtures.

The unreleased refresh-token hardening migration is intentionally disruptive:
it clears every legacy plaintext session refresh value, adds hash-only current
token storage and consumed-token history, and therefore requires existing
refresh sessions to reauthenticate. Access sessions continue only for their
remaining access-token lifetime. The cleared bearer values cannot be recovered
by running the migration down; rollback requires the pre-upgrade database if
preserving those sessions is necessary.

## Non-negotiable safety boundary

- Pin the target release by version and digest; do not upgrade production from
  a mutable `latest` reference.
- Back up and restore-test the database and all key/configuration state before
  upgrading. See [backup-restore.md](./backup-restore.md).
- Rehearse the exact source/target versions and database engine on an isolated
  copy first.
- Treat a database touched by a newer release as incompatible with an older
  binary unless that exact downgrade path has published evidence.
- Rollback after schema change means restoring the pre-upgrade database and key
  state together, not merely switching the binary or image tag.

## Encryption-envelope compatibility boundary

The keyring-capable release reads both legacy AES-GCM `nonce || ciphertext`
values and its new versioned ciphertext envelope. Older binaries read only the
legacy form. As soon as an upgraded process writes or refreshes any encrypted
TOTP, SMTP, OAuth/upstream, billing, connected-account, SIEM, webhook, or SAML secret,
an older binary may be unable to use that record even when given the same key.

Upgrade all writers under a maintenance window and retain the existing
`ENCRYPTION_KEY`. Do not permit mixed old/new binaries to mutate encrypted
records. Rollback to the older binary is safe only if the new binary accepted no
secret writes. Otherwise roll forward, or restore the pre-upgrade database and
its matching encryption configuration together. The `rewrap-secrets` database
command deliberately upgrades values to V2 and therefore does not make an
in-place downgrade safe. The staged keyring procedure and remaining limitations are in
[key-rotation.md](./key-rotation.md).

## Standalone SQLite upgrade

The release wrapper accepts `AUTHOS_RELEASE_TAG`; the extracted bundle's
installer stops the current service, replaces `/usr/local/bin/authos`, preserves
managed state, renders the service, restarts it, and waits for readiness.
Migrations run during API startup.

Each install atomically replaces `/opt/authos/LICENSE`,
`/opt/authos/AGPL-3.0.txt`, and `/opt/authos/README.txt` alongside the manager;
the README records the bundle's exact corresponding-source tag. Installing a
previous bundle replaces those notices with that bundle's notices, but does not
make a database downgrade safe. There is no automated uninstaller. Preserve
the notices and required backup evidence before manually removing the service,
binary, units, `/opt/authos`, or managed data; managed data must never be removed
as an incidental binary rollback.

**Operator procedure — repository-aligned, source/target drills not yet
published:**

1. Record the current `/health` response and artifact version.
2. Complete and verify a cold backup.
3. Download `install.sh`, the matching archive, checksums, and attestation for
   the exact target release; verify them using
   [release-verification.md](../release-verification.md).
4. Run the pinned installer during a maintenance window.
5. Verify readiness, the reported build version, logs, login/refresh, tenant
   boundaries, and configured protocol journeys.

```bash
TARGET_VERSION=vX.Y.Z
curl -fsSL -o install.sh \
  "https://github.com/drmhse/AuthOS/releases/download/${TARGET_VERSION}/install.sh"
chmod +x install.sh
sudo AUTHOS_RELEASE_TAG="${TARGET_VERSION}" ./install.sh
curl -fsS http://127.0.0.1:3001/health
curl -fsS http://127.0.0.1:3001/health/ready
sudo systemctl --no-pager --full status authos.service
sudo journalctl -u authos.service --since '-15 minutes' --no-pager
```

Adjust the local URL for a configured port. Do not interpret readiness alone as
a successful upgrade; it checks database connectivity, not application data or
external dependencies.

## Docker upgrade

The generated bootstrap configuration pins an image string in
`authos.config.json`. Update it to the exact backend-specific release image,
regenerate outputs, inspect the diff, pull the image, and recreate the AuthOS
service only after a backup and rehearsal.

**Planned validation sequence — not yet a published compatibility guarantee:**

```bash
node scripts/authos-bootstrap.js
docker compose -f .authos/docker-compose.yml config --quiet
docker compose -f .authos/docker-compose.yml pull authos
docker compose -f .authos/docker-compose.yml up -d --no-deps authos
curl -fsS http://127.0.0.1:3001/health
curl -fsS http://127.0.0.1:3001/health/ready
docker compose -f .authos/docker-compose.yml logs --since=15m authos
```

`node scripts/authos-bootstrap.js` renders files but does not start services
without `--up`. Confirm the generated image line is the intended immutable version
before the `pull`/`up` commands. PostgreSQL and MySQL engine upgrades are
separate operations and must follow their vendor's compatibility procedure.

## Rollback and failed migration

If the new process fails before touching the database, restoring the previous
binary/image may be sufficient, but that must be established from migration
logs and database inspection. When there is any uncertainty, use the full
restore path:

1. stop AuthOS and prevent restarts;
2. preserve the failed environment for investigation;
3. provision the exact previous AuthOS release in an isolated target;
4. restore the complete pre-upgrade database plus matching signing/encryption
   state;
5. verify the restored target before routing traffic to it.

Do not run migration `down` commands in production as an improvised rollback.
The migration history contains data/schema changes for which reverse behavior
is not established as safe, and no downgrade matrix is currently published.

## Evidence still required

- an inventory of supported upgrade origins for every backend;
- source-version-to-target-version tests for every declared origin and backend
  (only one representative SQLite origin is currently covered);
- crash/partial-migration and disk-full recovery exercises;
- explicit reversible and irreversible migration classification;
- failed-upgrade and full-restore drill reports;
- multi-replica migration and rolling-upgrade qualification before any HA claim.
