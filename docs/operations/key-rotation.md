# Cryptographic key rotation

This document separates the currently implemented single-key configuration
from the overlap and recovery behavior still needed for production-grade key
rotation. Do not change production keys solely from this page without first
rehearsing the exact deployment and client behavior.

## Current key inventory

| Material | Current source | Current behavior |
| --- | --- | --- |
| JWT RSA signing key, public key, and `kid` | Standalone `state.json`, bootstrap `.authos/state.json`, or direct environment variables | The API loads one RS256 key pair at startup and publishes exactly one JWK. There is no previous-key verification set or overlap window. |
| `ENCRYPTION_KEY` | Standalone/bootstrap state or direct environment | Required for normal API startup. One 32-byte AES-256-GCM key encrypts selected stored secret material. There is no key ring or committed re-encryption command. |
| `DEVICE_TRUST_SECRET` | Standalone/bootstrap state or direct environment | One secret is loaded at startup. No overlap mechanism or public rotation drill is documented. |
| SAML signing certificates/keys | Database-managed SAML configuration | Separate from the platform JWT key. Rotation requires its own interoperability procedure and is not covered by changing `JWT_*`. |
| TLS private keys | Caddy or the operator's TLS terminator | Outside the AuthOS JWT key lifecycle. |

The state files and rendered environment contain secrets. Never paste them into
issues, logs, command history, or drill reports.

## JWT rotation boundary

Replacing `JWT_PRIVATE_KEY_BASE64`, `JWT_PUBLIC_KEY_BASE64`, and `JWT_KID`, then
restarting, causes newly issued tokens and JWKS to use the new key. Because the
API retains only one decoding key, access tokens signed by the old key will no
longer validate in AuthOS after restart. Downstream verifiers may also fail
until they refresh JWKS.

Therefore seamless scheduled JWT rotation and emergency rollover are **not yet
verified**. An operator can perform a disruptive replacement only with an
explicit reauthentication/session-impact plan and tested downstream JWKS cache
behavior.

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

## Minimum disruptive JWT replacement exercise

**Planned exercise — no passing public drill exists yet:**

1. Take a complete recoverable backup and record the current `kid`.
2. Generate and protect a new key pair; validate private/public correspondence.
3. Inventory downstream JWKS cache lifetimes and arrange a reauthentication
   window.
4. Replace the three JWT values atomically in the managed source of truth.
5. Restart one isolated AuthOS environment and wait for readiness.
6. Confirm JWKS exposes only the expected new `kid`, a newly issued token uses
   it, and every downstream verifier accepts it.
7. Explicitly confirm the expected outcome for an old access token and for a
   database-backed refresh journey.
8. Retain the old key only for the approved recovery period, then destroy it
   under dual control and record the event.

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
*missing* key; it does not accept a malformed configured key. Do not expose
shared, staging, production, or otherwise persistent data to a process started
in this mode.

Do **not** replace `ENCRYPTION_KEY` as a routine rotation step. Existing
ciphertext is not tagged with a selectable key version, and the current service
has no dual-read/re-encryption workflow. Replacing the key can make encrypted
stored credentials unreadable. A safe implementation needs versioned key IDs,
old/new decrypt support, transactional re-encryption, verification, and a
tested rollback.

Fail-closed startup prevents new normal deployments from silently operating
without the key. It does **not** discover, migrate, or rotate plaintext values
written by older releases or development-mode processes. Operators upgrading
such a database must inventory legacy plaintext columns, implement and verify a
separate data migration, and rotate affected upstream credentials before
claiming encryption at rest.

Treat `DEVICE_TRUST_SECRET` similarly until token/cookie impact and overlap
behavior are covered by an automated test and operator drill.

## Compromise response

For suspected compromise, preserve evidence, restrict access, stop further key
use where appropriate, and follow the private reporting path in
[SECURITY.md](../../SECURITY.md). The exact response can require JWT
replacement, session revocation, upstream credential replacement, SAML/TLS
certificate action, or full secret re-encryption; these are different keys and
must not be conflated.

The project still needs an implemented multi-key JWT/JWKS model, cache/overlap
contract, encryption-key rewrap mechanism, SAML rotation interoperability
tests, and published normal/emergency rotation drill reports.
