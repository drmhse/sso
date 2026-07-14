# Cryptographic key rotation

AuthOS implements a bounded JWT verification overlap, but production-grade
rotation still depends on deployment and downstream-cache evidence. Do not
change production keys solely from this page without first rehearsing the exact
deployment and client behavior.

## Current key inventory

| Material | Current source | Current behavior |
| --- | --- | --- |
| JWT RSA signing key, public key, and `kid` | Standalone `state.json`, bootstrap `.authos/state.json`, or direct environment variables | The API signs only with one active RS256 key. `JWT_PREVIOUS_PUBLIC_KEYS_JSON` optionally retains up to ten previous public keys keyed by `kid`; validators and JWKS use the active-plus-previous set. |
| `ENCRYPTION_KEY`, `ENCRYPTION_KEY_ID`, `ENCRYPTION_PREVIOUS_KEYS` | Managed state for the active key; bootstrap state or direct environment for the keyring | Normal startup requires one active 32-byte AES-256-GCM key. New V2 ciphertext authenticates its key ID plus table/record/field context; a read-only previous-key ring decrypts V2, V1, and legacy unversioned ciphertext. `rewrap-secrets` provides dry-run verification and bounded, resumable CAS rewriting. Standalone managed-state support for durable previous-key configuration is still missing. |
| `DEVICE_TRUST_SECRET` | Standalone/bootstrap state or direct environment | One secret is loaded at startup. No overlap mechanism or public rotation drill is documented. |
| SAML signing certificates/keys | Database-managed per-service SAML configuration | One valid active key signs. Rotation publishes the former certificate as verification-only for seven days, capped at two previous certificates; metadata excludes expired or retired certificates. The authenticated service-management API can retire every overlap immediately. |
| TLS private keys | Caddy or the operator's TLS terminator | Outside the AuthOS JWT key lifecycle. |

The state files and rendered environment contain secrets. Never paste them into
issues, logs, command history, or drill reports.

## JWT rotation boundary

`JWT_PREVIOUS_PUBLIC_KEYS_JSON` is a JSON object whose property names are old
key IDs and whose values are base64-encoded RSA public PEM files. It must never
contain private keys. For example, with placeholders only:

```text
JWT_PREVIOUS_PUBLIC_KEYS_JSON={"authos-old":"BASE64_PUBLIC_PEM"}
```

At startup AuthOS rejects malformed JSON, invalid keys, an empty `kid`, more
than ten previous keys, the active `kid` in the previous ring, and the same
public-key material assigned to multiple IDs. A JWT must name a configured
`kid`; AuthOS then verifies its RS256 signature with only that key. New tokens
always use `JWT_PRIVATE_KEY_BASE64` and `JWT_KID`. JWKS publishes the active key
first and every retained previous public key after it.

This makes a scheduled overlap possible, but seamless production rollover is
still **unverified**. The repository has local old/new, retirement, negative,
and JWKS regressions; it does not yet have a release-candidate drill through
real downstream JWKS caches or a published maximum cache lifetime. An emergency
compromise is not a normal overlap: do not retain a suspected compromised key
merely to preserve old tokens.

Generate staged RSA material on a protected Linux host as follows. This creates
files only; it does not modify AuthOS:

```bash
umask 077
KEY_DIR=$(mktemp -d)
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  -out "${KEY_DIR}/jwt-private.pem"
openssl pkey -in "${KEY_DIR}/jwt-private.pem" -pubout \
  -out "${KEY_DIR}/jwt-public.pem"
openssl pkey -in "${KEY_DIR}/jwt-private.pem" -check -noout
openssl pkey -pubin -in "${KEY_DIR}/jwt-public.pem" -text -noout >/dev/null
printf 'JWT_KID=authos-%s\n' "$(openssl rand -hex 8)"
base64 -w 0 "${KEY_DIR}/jwt-private.pem"
printf '\n'
base64 -w 0 "${KEY_DIR}/jwt-public.pem"
printf '\n'
```

Transfer the values through the deployment's secret-management channel. Do
not store the printed values in a shell transcript. For standalone installs,
the source of truth is the `jwt` object in the managed `state.json`; running
`authos-apply apply --bundle-dir /opt/authos` renders it into `/etc/authos/authos.env`
and restarts the service. For bootstrap Compose, `.authos/state.json` is the
source used when outputs are regenerated. Directly editing only the rendered
environment is not durable in either managed flow.

Managed state uses `jwt.previousPublicKeys` for the same `kid` to base64-public-
PEM object. The renderers emit it as `JWT_PREVIOUS_PUBLIC_KEYS_JSON`. Protect
state files as before: public verification keys are not secret, but those files
also contain the active private key and other credentials.

## Scheduled JWT overlap exercise

**Planned exercise — no passing public drill exists yet:**

1. Take a complete recoverable backup and record the current `kid`.
2. Generate and protect a new key pair; validate private/public correspondence.
3. Inventory downstream JWKS cache lifetimes and choose an overlap longer than
   both the maximum remaining old-token lifetime and verified cache lifetime.
4. Atomically replace the active three JWT values and add the old `kid` and
   public key to `JWT_PREVIOUS_PUBLIC_KEYS_JSON` in the managed source of truth.
5. Restart one isolated AuthOS environment and wait for readiness.
6. Confirm JWKS exposes exactly the new and retained old `kid`, newly issued
   tokens use only the new `kid`, and old and new tokens validate at AuthOS and
   every downstream verifier.
7. Exercise a database-backed refresh journey and prove refreshed tokens use
   the new key. Observe the full overlap and cache-expiry window.
8. Remove the old public key, restart, and prove old tokens fail while new
   tokens and JWKS continue to work. Destroy retired private material under the
   approved control and record the event.

```bash
AUTHOS_URL=https://auth.example.com
curl -fsS "${AUTHOS_URL}/.well-known/jwks.json"
curl -fsS "${AUTHOS_URL}/health/ready"
```

## Encryption and device-trust keys

Normal server startup rejects a missing key and rejects values that are not
exactly 64 hexadecimal characters. The managed standalone and bootstrap flows
generate and persist this material automatically. Direct deployments must
generate it with a cryptographically secure source such as
`openssl rand -hex 32`, inject it through their secret-management channel, and
back it up together with the database.

`AUTHOS_ALLOW_UNENCRYPTED_DEVELOPMENT=true` is an explicit compatibility escape
hatch for disposable development and test databases only. It permits a
*missing* key only when `ENCRYPTION_KEY_ID` and `ENCRYPTION_PREVIOUS_KEYS` are
also unset; it does not accept a malformed active key or orphaned keyring
metadata. Do not expose shared, staging, production, or otherwise persistent
data to a process started in this mode.

New encrypted writes use a versioned binary envelope containing the format
version and `ENCRYPTION_KEY_ID`. The complete envelope header is AES-GCM
associated data, so changing the version or key ID invalidates authentication.
V2 also authenticates the physical table, stable row ID, and encrypted column
name as length-delimited associated data, so ciphertext cannot be transplanted
between records or secret fields. Values written by older versions as
`nonce || ciphertext` remain readable only through the maintenance scanner:
AuthOS tries the active key followed by each configured previous key before
rewriting them as V2.

Configure rotation inputs as follows:

```dotenv
ENCRYPTION_KEY=<new 64-character hexadecimal key>
ENCRYPTION_KEY_ID=key-2026-07
ENCRYPTION_PREVIOUS_KEYS=key-2026-01=<old 64-character hexadecimal key>
```

Bootstrap Compose persists the equivalent protected fields in
`.authos/state.json` and renders them into `authos.env`:

```json
{
  "encryptionKey": "<new 64-character hexadecimal key>",
  "encryptionKeyId": "key-2026-07",
  "encryptionPreviousKeys": {
    "key-2026-01": "<old 64-character hexadecimal key>"
  }
}
```

Regenerate bootstrap outputs after changing that state. The standalone manager
does not yet expose equivalent durable previous-key fields; standalone operators
must use a protected, durable service-environment override and verify it survives
re-render/restart, or defer rotation. Do not edit only a generated environment
file and assume the change will persist.

Key IDs must be unique and contain 1-64 ASCII letters, digits, `.`, `_`, or
`-`. `ENCRYPTION_PREVIOUS_KEYS` is comma-separated. Previous keys are read-only;
all new writes use the active key. Missing referenced keys, malformed envelopes,
unsupported envelope versions, and authentication failure produce distinct
failures without falling back to plaintext.

### Safe deployment and rotation boundary

The new reader is backward-compatible with old ciphertext, but an older AuthOS
binary cannot read the new envelope. Therefore this change is **not** safe for
a mixed-version rolling deployment that accepts secret writes.

1. Back up the database and all active/previous keys, then verify restoration in
   an isolated environment.
2. Stop secret-mutating traffic and upgrade every AuthOS instance before
   reopening writes. Multi-node operation is not generally supported, so this
   requires an operator-controlled maintenance window rather than a claimed
   zero-downtime rollout.
3. With every API and worker still stopped, run the release's database migration
   job so the webhook ciphertext columns exist. Do not use a serving API process
   as the migration job: its worker could claim a legacy webhook before rewrap.
   The migration is per-column idempotent so a MySQL DDL autocommit interruption
   can be retried. `rewrap-secrets` intentionally does not mutate schema and
   must not be run against the pre-migration schema.
4. With the existing key and a stable key ID (or compatibility ID `default`),
   run the release binary's dry-run/apply/dry-run sequence below before starting
   any API or worker. Resolve every error and require a final zero-change scan.
   Normal encrypted startup independently repeats that complete scan in
   read-only mode after schema migration and before bootstrap, writer-pool
   creation, external service checks, background tasks, or HTTP routing. It
   refuses to start if any inventoried row needs rewrap or plaintext migration;
   startup never applies secret changes itself. The scan uses stable-ID cursor
   pages of 100 rows and a five-minute wall-clock deadline, so its memory is
   bounded and a stalled database cannot block startup forever.
5. Start the upgraded version and verify representative TOTP, SMTP, upstream
   OAuth, billing, connected-account token, SIEM, webhook, and SAML signing
   reads before changing key material.
6. Generate a new key, make it the active `ENCRYPTION_KEY`, assign a new
   `ENCRYPTION_KEY_ID`, and place the old ID/key in
   `ENCRYPTION_PREVIOUS_KEYS`. Restart in the same maintenance discipline.
7. Verify old ciphertext reads and confirm newly written ciphertext records the
   new key ID where the schema has a key-ID column.

`rewrap-secrets` inventories 14 secret-bearing values in ten current tables.
It authenticates already-active values in their table/record/field context,
rewrites legacy/V1 and previous-key values as V2, repairs key-ID metadata after
sibling fields succeed, and safely migrates unambiguous identity,
connected-account, SIEM, and webhook plaintext compatibility values.
Authenticated envelopes containing empty plaintext are still rejected for
required OAuth, billing, TOTP, SAML-signing, OAuth/OIDC-upstream, and webhook
secret fields; encryption is not treated as proof that required material is
usable. SMTP, SIEM, identity, and connected-account optional fields retain their
documented empty/absent semantics.
The default is read-only:

```bash
./sso_sqlite rewrap-secrets --dry-run --batch-size 100
./sso_sqlite rewrap-secrets --apply --batch-size 100
./sso_sqlite rewrap-secrets --dry-run --batch-size 100
```

Use the matching `sso_psql` or `sso_mysql` binary for those deployments. The
command reads the normal database configuration plus the complete active and
previous encryption keyring. It connects without running schema migrations and
prints a JSON report containing counts and identifiers, never secret values.
`--max-batches N` bounds the number of batches that contain changes. A repeat
run skips authenticated active values without consuming that limit, so an
interrupted or deliberately bounded apply can resume by rerunning the same
command. Each changed batch is planned completely before a transaction begins;
a bad sibling or tampered value leaves that batch unchanged.

Prefer stopping every API and worker that can mutate secrets for the apply and
final verification scan until multi-writer qualification exists. Every update
does use compare-and-swap predicates: a concurrent change aborts and rolls back
the affected batch rather than being overwritten. Rerun after quiescing that
writer. Keep a verified database/key backup and preserve every old key
throughout the run.

The runtime gate starts before writers in that process, but it is not a global
database lock or proof that another replica is quiescent. An unsupported
concurrent writer could change a previously scanned row or insert behind a
cursor. Stop every old and peer process during migration/rewrap and first
startup; PostgreSQL/MySQL and multi-replica race qualification remains open.

The command fails closed on plaintext/encrypted OAuth disagreement. SIEM text
that is valid base64 but cannot be decrypted is deliberately reported as
ambiguous and is not guessed to be plaintext. Replace or manually classify that
credential before retrying. Empty upstream-provider client-secret blobs are a
documented sentinel only for SAML providers and are counted as skipped; an
OAuth/OIDC row without a decryptable client secret fails readiness because the
current runtime supports confidential upstream clients only. A webhook row
without either its legacy or encrypted signing secret likewise fails readiness,
even while disabled. Legacy `webhooks.secret` is migrated into
`secret_encrypted` and cleared; webhook delivery refuses the plaintext fallback.

Identity and connected-account V2 values authenticate the exact
`access_token_encrypted` or `refresh_token_encrypted` physical field. Their
runtime readers reject a populated plaintext compatibility column whenever an
encryption service is configured, even if ciphertext is also present. The only
plaintext read path is the explicitly unencrypted disposable-development mode;
normal startup catches such rows before any token refresh or provider-token
handler can run.

**Do not remove a previous key merely because an apply run completed.** Retain
it with every database backup that may reference it. At minimum, require a
subsequent complete dry-run with zero changed rows and no ambiguity/error, then
exercise representative SMTP, TOTP, OAuth, SAML, billing, connected-account,
webhook, and SIEM reads using an isolated restored copy. P2-07 remains open for
PostgreSQL/MySQL and multi-writer qualification, identity/connected-account
compatibility-column disposition, and a published key-retirement and
backup/restore drill.

### Rollback warning

Rollback to an older binary is safe only before the upgraded process has written
any versioned envelope. After that point, roll forward with the keyring-capable
binary or restore the pre-upgrade database snapshot together with its matching
key configuration. Restoring only the old binary or only the old key can strand
new ciphertext. Never remove the active or previous key from secret management
until the corresponding backup-retention window has expired.

Fail-closed startup prevents new normal deployments from silently operating
without the key. The rewrap command discovers and migrates only the explicitly
inventoried, unambiguous compatibility values described above; it does not make
every historical plaintext storage path safe. Operators must resolve reported
ambiguity, verify migrated webhook/SIEM and all other relevant runtime paths,
and rotate affected upstream credentials before claiming encryption at rest.

Treat `DEVICE_TRUST_SECRET` similarly until token/cookie impact and overlap
behavior are covered by an automated test and operator drill.

## SAML signing-certificate rollover boundary

`POST /api/organizations/{org}/services/{service}/saml/certificate` installs one
new active signing key. The former active certificate becomes metadata-only for
seven days (or until its X.509 expiry, whichever occurs first). Metadata emits
the active certificate first and no more than two eligible previous
certificates. New assertions and responses select only the valid active key;
expired, future, previous, or manually retired keys cannot sign.

Rotation serializes on the service row and deactivates every active-key row
before inserting the replacement. PostgreSQL and SQLite additionally enforce
the single-active-key invariant with a partial unique index. MySQL has no
equivalent partial index in the shipped schema, so its guarantee depends on
all writers taking the service-row lock; rotation deterministically retains
only the newest prior key for overlap and immediately retires any duplicate
active rows it encounters. Direct database key insertion is unsupported.

The authenticated certificate `GET` response reports `lifecycle_status` as
`healthy`, `expiring_soon` (30 days or less), `expired`, or `not_yet_valid`, as
well as `expires_in_seconds` and the exact published previous certificates with
their `publish_until` times. Alerting must poll this authenticated status and
page before `expiring_soon` becomes `expired`; AuthOS does not yet ship a
qualified external alert delivery path for this status.

After every service provider has accepted the active certificate, or
immediately after suspected compromise of a previous private key, call:

```text
DELETE /api/organizations/{org}/services/{service}/saml/certificate/overlap
```

The caller must have current service-management authority. The operation is
idempotent and does not replace or retire the active signer. Deleting the SAML
configuration retires both active and previous certificates in the same
database transaction. If the active private key may be compromised, generate
a new active certificate first, then retire the overlap; also force each SP to
refresh metadata because AuthOS cannot evict certificates already held in a
remote cache.

These are locally tested lifecycle semantics, not interoperability evidence.
Before production reliance, exercise scheduled rollover, forced metadata-cache
refresh, emergency retirement, clock skew, restored backups, and deletion
against at least three independent SP implementations on the exact release
candidate. PostgreSQL/MySQL runtime concurrency, multi-replica behavior, and
remote cache eviction remain unqualified.

## Identity compatibility-column retention decision

The nullable plaintext `access_token` and `refresh_token` columns on
`identities` and `connected_accounts` are retained temporarily as a migration
bridge; they are not a supported production storage mode. A normal production
startup requires the encryption service, encrypted writes clear the plaintext
columns, and the rewrap command migrates unambiguous compatibility values into
record/field-bound ciphertext before clearing them. The explicit development
no-key escape hatch can still use these columns and must never be used as
production evidence.

Do not drop the columns merely because one SQLite rewrap succeeds. A removal
migration is permitted only after all supported source versions can upgrade
through the bridge, PostgreSQL/MySQL and concurrent-writer rewrap tests pass,
restored backups complete representative identity and connected-account reads,
an inventory reports zero non-null compatibility values for the full retained
backup window, old encryption keys are safely retired, and the rollback policy
no longer promises a binary that needs the columns. Until every criterion is
recorded against a release candidate, keep the columns nullable, production
read-disabled by the mandatory encryption configuration, included in the
scanner, and excluded from production-readiness claims.

## Compromise response

For suspected compromise, preserve evidence, restrict access, stop further key
use where appropriate, and follow the private reporting path in
[SECURITY.md](../../SECURITY.md). The exact response can require JWT
replacement, session revocation, upstream credential replacement, SAML/TLS
certificate action, or full secret re-encryption; these are different keys and
must not be conflated.

If the active JWT private key may be compromised, replace it without placing
its public key in the previous ring, revoke affected AuthOS sessions, and
coordinate immediate JWKS refresh or key denial with every external verifier.
Previously cached JWKS can continue to trust the compromised key until those
verifiers refresh; the AuthOS overlap mechanism cannot force remote cache
eviction. No passing multi-verifier emergency drill is published yet.

The project still needs a measured JWT cache/overlap contract, all-database and
multi-writer rewrap qualification, SAML rotation interoperability tests,
and published normal and emergency rotation drill reports.
