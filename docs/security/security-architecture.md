# AuthOS security architecture

Status: implementation map, not a security or conformance guarantee

Reviewed: 2026-07-14

This document maps security-relevant behavior to the current repository. It
deliberately distinguishes source-visible mechanisms from verified controls.
See the [threat model](./threat-model.md) for abuse cases and open risks, and the
[tenant-resource inventory](./tenant-resource-inventory.md) for the isolation
surface.

## System and deployment boundary

The main process is a Rust/Axum HTTP API backed by one SeaORM database
connection configuration. Build features select SQLite, PostgreSQL, or MySQL.
The process also starts cleanup, refresh, metrics, event, webhook/email-job, and
buffered-audit work (`api/src/main.rs`, `api/src/jobs/`, `api/src/services/`).

The API binds to `SERVER_HOST`/`SERVER_PORT`; `BASE_URL` supplies the public
issuer/origin. TLS termination, firewalling, database encryption, filesystem
permissions, container isolation, and reverse-proxy policy are outside the
Rust process and must be supplied by the deployment. HSTS,
`X-Content-Type-Options`, and `X-Frame-Options` response headers are set by the
application, but HSTS is effective only over HTTPS (`api/src/main.rs`).

## Route security domains

| Domain | Authentication boundary | Source |
| --- | --- | --- |
| Public/authentication | No prior session; auth and device routes have IP rate-limit layers | `api/src/router.rs` |
| User and organization API | RS256 bearer JWT plus a matching non-expired database session | `api/src/middleware.rs` |
| Platform API | Authenticated user plus current database `is_platform_owner` | `api/src/router.rs`, `api/src/middleware.rs` |
| Service API | `X-Api-Key` resolved to a service principal and permission list | `api/src/middleware.rs` |
| SCIM API | Hashed bearer token resolved to one active, unexpired organization context | `api/src/middleware.rs` |
| SAML IdP endpoints | Public request initiation/metadata; protected service configuration and IdP-initiated route | `api/src/router.rs`, `api/src/handlers/saml.rs` |
| Webhooks from billing providers | Provider-specific verification in webhook handlers; no generic user session | `api/src/main.rs`, `api/src/handlers/webhook.rs` |
| Health and metrics | Health probes are public; metrics are disabled by default and require a configured bearer token when enabled | `api/src/main.rs`, `api/src/http_security.rs`, `api/src/router.rs` |

All routes receive a 30-second request timeout and a configurable streaming
request-body bound that defaults to 1 MiB. Dynamic CORS determines which browser
origins receive credentialed CORS headers; it is not relied on as server-side
authorization (`api/src/main.rs`, `api/src/http_security.rs`,
`api/src/middleware.rs`).

## Identity, authorization, and tenant context

### Authenticated user

An ordinary access token contains `sub`, email, platform-owner flag, `jti`,
optional organization/service/resource/scope context, `iat`, and `exp`. The JWT
is signed with RS256. Middleware validates the JWT, hashes the exact token, and
requires a non-expired session row with that hash before loading the current
user and permissions from the database (`api/src/auth/jwt.rs`,
`api/src/middleware.rs`, `api/src/store/sessions.rs`).

The platform-owner check uses the freshly loaded/cached user model rather than
only trusting the token's flag. The user cache has a 30-second TTL; permission
cache has a 60-second TTL. Some authorization changes explicitly invalidate
caches, but comprehensive invalidation evidence is not yet published
(`api/src/state.rs`, `api/src/main.rs`).

### Tenant authorization

Organizations are the tenant root. Services belong to an organization; many
other records derive tenant context through a service or user. Handlers combine:

- membership rows with built-in roles such as owner/admin/member;
- relationship tuples stored as namespace/object/relation permissions;
- resource-specific checks that bind a service, role, webhook, SCIM token, or
  configuration record to the organization resolved from the route; and
- active-organization checks for selected feature routes.

The database is shared and no database row-level-security policy was found.
Isolation is therefore an application invariant: every lookup and mutation
must carry or derive the correct tenant predicate. The source contains many
specific checks and tests, but this architecture does not claim complete
coverage until the inventory matrix is automated.

### Service and provisioning principals

API keys contain a visible random prefix and a 32-byte random secret component.
Only SHA-256 of the full value is stored; verification compares hashes without
early byte exit. Middleware checks expiry, loads the bound service, and exposes
the stored permission list (`api/src/auth/api_key.rs`,
`api/src/middleware.rs`).

SCIM tokens are random UUID-derived values stored as SHA-256 hashes with an
active flag and optional expiry. Middleware binds the request to the token's
`org_id` and rejects a conflicting `X-Organization-ID`. Handlers use that
context for user membership and group operations
(`api/src/store/scim_tokens.rs`, `api/src/handlers/scim/`).

Hashing is appropriate for high-entropy bearer values only if generation,
single display, transport, rotation, and database handling are also correct;
those lifecycle properties still need end-to-end evidence.

## Credential and secret storage

| Material | Current representation | Status |
| --- | --- | --- |
| User passwords | Argon2 password-hash string with random salt | Source-evidenced in `api/src/handlers/auth/password.rs`; parameter policy and upgrade strategy unverified. |
| MFA backup codes | Individual Argon2 hashes | Source-evidenced in `api/src/auth/mfa.rs` and TOTP store paths. |
| TOTP secret | AES-256-GCM ciphertext plus key ID | Source-evidenced; key ID is currently the constant `default`, so rotation lifecycle is a gap. |
| Access-token session reference | SHA-256 hash of the complete JWT | Source-evidenced; the signed JWT itself remains bearer material at clients. |
| Refresh token | Plaintext session column | Gap: hash or encrypt at rest and add reuse-family response. |
| Email verification, password reset, magic-link token | SHA-256 hash plus expiry and used/deletion state | Source-evidenced; concurrent one-time use requires full matrix testing. |
| API key / SCIM token | Prefix plus SHA-256 hash | Source-evidenced. |
| Service client secret | Hash in service record | Source-evidenced at schema level; issuance/rotation tests required. |
| Organization OAuth, billing, SMTP, upstream-provider credentials | AES-256-GCM ciphertext plus key ID | Source-evidenced in entity/store/handler paths. |
| SAML signing private key | AES-256-GCM ciphertext; public certificate stored separately | Source-evidenced in `api/src/handlers/saml.rs`. |
| Connected-account provider tokens | Encrypted columns exist and current handlers accept an encryption service; legacy plaintext columns also exist | Partial; prove all writes/reads reject plaintext fallback before claiming encrypted storage. |
| Webhook signing secret | Plaintext database column | Gap. |
| SIEM API key/auth header | Plaintext database columns | Gap. |
| OAuth PKCE verifier and transaction state | Plaintext, expiring database state | Expected server-side transaction material, but database/backups must be protected and cleanup tested. |
| JWT private/public key and data-encryption key | Environment variables | The data-encryption key is required for normal startup and validated as 64 hexadecimal characters. Material remains operator-controlled; there is no integrated secret-manager or rotation lifecycle. |

`EncryptionService` requires a 32-byte hex key, generates a random 96-bit
nonce, and uses AES-256-GCM. Ciphertext is stored as `nonce || ciphertext`
(`api/src/encryption/mod.rs`). The construction provides authenticated
encryption, but there is no associated-data binding to tenant/resource IDs and
no multi-key decrypt registry. Key backup, rotation, compromise, and migration
are unverified.

Server startup fails before database initialization when `ENCRYPTION_KEY` is
missing or malformed. The narrowly named
`AUTHOS_ALLOW_UNENCRYPTED_DEVELOPMENT=true` escape hatch permits only a missing
key and is limited to disposable development/test data. This startup control
does not rewrite legacy plaintext database columns or prove that every storage
path is encrypted. Existing plaintext values require an explicit migration,
verification, and credential rotation plan.

## Authentication transactions

### Password and account recovery

Password registration and changes hash with Argon2. Login performs an Argon2
verification even when no usable account password exists, reducing a direct
timing distinction. Verified-email, organization status/context, risk, MFA, and
session creation are applied in the handler flow. Reset tokens expire after an
hour, are conditionally marked used, and password reset deletes all user
sessions (`api/src/handlers/auth/password.rs`).

The implementation still needs measured enumeration tests, password-policy
documentation, lockout/credential-stuffing analysis, compromised-password
policy decisions, and transaction-failure tests around token consumption and
password update.

### MFA

TOTP uses six digits, a 30-second step, and a one-step skew window. Backup codes
are random alphanumeric values stored as Argon2 hashes. MFA login uses a
five-minute pre-auth JWT and consumes its `jti` under a database-backed
distributed lock before session creation (`api/src/auth/mfa.rs`,
`api/src/handlers/auth/mfa.rs`). MFA verification and setup routes have tighter
IP rate limits.

Recovery assurance, factor-reset policy, backup-code atomicity, pre-auth replay
across replicas, and platform-owner MFA requirements are not yet established as
release guarantees.

### Magic links and passkeys

Magic-link tokens expire after 15 minutes, are stored hashed, and are deleted
before authentication continues. Stored context binds service and redirect
parameters in the reviewed flow (`api/src/store/magic_links.rs`,
`api/src/handlers/auth/magic.rs`).

Passkeys use `webauthn-rs`. Registration requires an authenticated user;
authentication begins from a scoped user lookup. Serialized ceremony state is
stored for five minutes and deleted before completion. RP configuration is
enabled only for localhost or a domain-backed HTTPS `BASE_URL`, and successful
authentication updates the credential counter (`api/src/main.rs`,
`api/src/services/webauthn.rs`, `api/src/handlers/auth/passkeys.rs`).

Cross-origin, counter-regression, discoverable-credential, concurrent replay,
and account-enumeration behavior require dedicated evidence.

## Token and session model

| Token profile | Format and audience | Validation boundary |
| --- | --- | --- |
| Platform, organization, or service access token | RS256 `Claims`; `platform`, `org:<slug>`, or `service:<org>/<service>` | Configured issuer and required audience everywhere; derived profile audience at AuthOS authenticated API middleware. |
| Resource-scoped access token | RS256 `Claims`; registered absolute resource URI | Configured issuer everywhere; exact resource at token exchange and at each external resource server. Rejected by AuthOS authenticated API middleware. |
| MFA pre-authentication token | RS256 `Claims`; preserves the eventual access-token profile and carries `mfa_required` | Configured issuer and required audience, five-minute expiry, `mfa_required`, and one-time `jti` consumption. |
| Impersonation token | RS256 `Claims` with `act`; `impersonation-session` | Configured issuer, fixed AuthOS audience profile, 15-minute expiry, and actor checks. |
| ID-JAG authorization grant | RS256 `IdJagClaims`, `typ=oauth-id-jag+jwt`; AuthOS issuer URL audience | Separate validator enforces type, configured issuer, expected audience, expiry, and one-time database grant. |
| Refresh token | Opaque UUID stored with a session; no JWT audience | Conditional database rotation, session context, and expiry checks. |

- Access-token lifetime is configured by `JWT_EXPIRATION_HOURS` (default 24).
- Refresh tokens are issued for 30 days in reviewed authentication paths and
  rotate using a compare-and-update operation.
- Impersonation tokens expire after 15 minutes, carry an `act` actor claim and
  the fixed `impersonation-session` audience, and do not use an ordinary
  session-row check in middleware.
- MFA pre-auth tokens expire after five minutes and carry `mfa_required` and
  `mfa_verified` state.
- ID-JAG authorization grants expire after five minutes and validate their
  custom type, issuer, and expected audience.

Ordinary access-token validation fixes the algorithm to RS256, requires `exp`,
`iss`, and `aud`, checks expiration, and compares `iss` to the configured
issuer (`api/src/auth/jwt.rs`). AuthOS authenticated API middleware accepts only
the audience derived from the token's platform, organization, service, or
impersonation profile, so a token minted for an external resource is rejected.
OAuth token exchange validates the exact requested resource audience. The
generic validator deliberately does not assume one audience across all
profiles: MFA pre-authentication and logout flows preserve or inspect tokens
whose audience may be an external resource. Token profiles other than ID-JAG
still share the same `Claims` structure without an explicit `typ`, and external
resource servers remain responsible for enforcing their own configured
audience. A complete cross-profile confusion and replay suite remains required.

Sessions store token hash, expiry, optional refresh token and expiry, optional
organization slug, service ID, resource, user agent, and IP address. Revocation
deletes session rows. Cache staleness, logout across token types, impersonation
revocation, refresh replay response, and multi-device semantics require a
published contract.

## OAuth/OIDC and device authorization

The authorization entry points persist a CSRF state plus flow context,
expiration, redirect URI, optional PKCE verifier, tenant/service context, and
requested resource/scopes. Callback paths retrieve and delete state before
upstream token exchange. PKCE is generated for upstream authorization and is
mandatory for service types treated as public. Service redirects are checked
against registered redirect URIs in reviewed paths
(`api/src/handlers/auth/oauth.rs`, `api/src/auth/sso.rs`,
`api/src/store/oauth_states.rs`).

OIDC discovery and a single-key JWKS are public. The discovery document
advertises authorization code, device code, token exchange, and JWT-bearer
profiles (`api/src/main.rs`). Advertisement is not conformance evidence. There
is no committed OpenID/OAuth conformance output, and the single-key JWKS design
does not provide an overlapping key-rotation window.

Device authorization persists expiring device/user codes and status, applies a
separate IP rate limit, and exchanges authorized state for tokens. Polling,
slow-down behavior, concurrent exchange, client/resource binding, and expiry
need protocol tests.

## SAML architecture

The SAML IdP surface is service-scoped. Configuration and certificate
management require service-management authorization. Private signing keys are
generated per service and AES-GCM encrypted. The IdP validates configured
organization/service, active status, ACS equality, destination when supplied,
and issuer. AuthnRequest parsing rejects DTD declarations, unknown entity
references, malformed XML/attributes, and invalid or duplicate request roots;
HTTP-Redirect decoding accepts raw DEFLATE with or without an XML declaration,
rejects encoded requests above 262,144 bytes, and caps expanded or POST-binding
XML at 1,048,576 bytes. Focused unit regressions cover these checks, decompression
limits, and escaped-value decoding. The IdP stores 15-minute request state.
Generated metadata, assertions, responses, and logout responses use structural
XML writers that escape configuration, request, and user values. Assertions contain
`NotBefore`, `NotOnOrAfter`, audience, destination, and optional
`InResponseTo`, and may sign the assertion and/or response
(`api/src/handlers/saml.rs`).

Canonicalization now rejects malformed XML instead of signing partial output.
The XML-signature code remains an in-repository construction, and no committed
canonicalization/signature-wrapping/interoperability suite proves it. The
reviewed AuthnRequest receiver does not validate request signatures. Most
importantly, upstream SAML response processing rejects every response because
signature verification is explicitly unimplemented
(`api/src/handlers/auth/upstream_saml.rs`). Upstream SAML is therefore not an
implemented authentication path despite configuration and initiation code.

## SCIM architecture

SCIM routes are isolated behind organization-bound SCIM bearer-token
middleware. User operations filter/list by the token organization and verify
membership for specific IDs. Group behavior currently represents the
organization as a group and validates the group ID against token organization
(`api/src/handlers/scim/`).

The source contains parser and handler tests, but no public interoperability
matrix. Supported filter grammar, pagination, PATCH semantics, idempotency,
deprovisioning, group semantics, and error schemas must be documented from
tests rather than inferred from the route list.

## Browser, network, and outbound controls

- Dynamic CORS allows the platform/API origins, verified active organization
  domains, and registered service redirect origins. Localhost, `127.*`, and
  `192.168.*` origins are allowed for development. Cache TTL is five minutes.
- Proxy headers are ignored unless enabled and the socket peer is explicitly
  trusted. Operators must ensure the framework receives the real peer socket
  address and that the proxy strips attacker-supplied forwarding headers.
- `SafeHttpClient` permits HTTP/HTTPS, rejects resolved private/reserved
  addresses, disables redirects, sets timeouts, and pins the validated DNS
  addresses for the request. It is used by reviewed webhook, SIEM, and
  configurable provider paths.
- Raw outbound HTTP clients also exist for fixed provider/billing/setup paths
  and token refresh. A machine-generated outbound-call inventory is still
  required before claiming comprehensive SSRF enforcement.
- Auth, device, MFA setup, and MFA verification routes use process-local IP
  rate limiting. Email/MFA helper limiters are also process-local. Multi-replica
  behavior is unverified.

## Audit and observability

AuthOS records login, organization, MFA, and platform audit entities and emits
bounded-label HTTP/authentication metrics. The audit actor batches writes,
retries lock/busy failures, falls back to direct inserts when its channel is
full, and flushes on graceful shutdown (`api/src/services/audit_actor.rs`).

This is not a durable audit guarantee: batches are cleared after retry
exhaustion, a closed channel reports an error without a synchronous fallback,
and abrupt process termination can lose buffered events. Audit completeness,
tamper resistance, retention, export, authorization, and secret/PII redaction
need explicit tests. `/metrics` is disabled unless a metrics bearer token is
configured, then compares a fixed-length digest in constant time; production
network restriction remains an operator responsibility.

## Cryptographic lifecycle

| Function | Current mechanism | Missing lifecycle evidence |
| --- | --- | --- |
| Access-token signing | One environment-supplied RSA private/public pair and `JWT_KID`; RS256 | Generation policy, protected storage, overlapping keys, rollover, compromise, rollback, verifier caching. |
| SAML signing | Per-service RSA key/certificate; AES-GCM-encrypted private key; validity fields | Standards interoperability, rotation overlap, metadata rollover, compromise/revocation, expiry alerting. |
| Application secret encryption | One 32-byte `ENCRYPTION_KEY`; AES-256-GCM with random nonce | Key hierarchy, multi-key decrypt, rotation/migration, backup/restore, AAD binding, secret-manager integration. |
| Password/backup-code hashing | Argon2 defaults with random salts | Parameter baseline, resource limits, periodic rehash, compatibility, breached-password decision. |
| High-entropy bearer lookup | SHA-256 hash | Entropy proof at every generator, constant-time verification where applicable, rotation and compromise response. |

No key-rotation or recovery guarantee should be made until the missing lifecycle
items are exercised against a release candidate and restored backup.

## Known gaps and unverified controls

1. Upstream SAML signature validation is not implemented and fails closed.
2. Access tokens do not yet carry explicit per-profile `typ` values, and a
   complete cross-profile confusion suite is not yet present. External resource
   servers must enforce their own configured audience.
3. Refresh tokens, webhook secrets, and SIEM credentials are stored in plaintext
   columns; connected-account plaintext compatibility columns also remain.
4. JWT JWKS and application encryption use single active keys without an
   implemented overlapping rotation lifecycle.
5. Tenant isolation is application-enforced with no database RLS defense in
   depth; comprehensive matrix evidence is incomplete.
6. `/metrics` has no dedicated listener and still needs deployment-level network
   restriction even though application bearer authentication is implemented.
7. Rate limiting is process-local and may reset or multiply across replicas.
8. A 1 MiB default global streaming request-body bound is implemented, but
   decompression, XML-specific, and crypto-work limits still need evidence.
9. Buffered audit logging can lose records after retry exhaustion, channel
   closure, or abrupt termination.
10. Public OAuth/OIDC conformance, SAML/SCIM interoperability, key-rotation,
    redaction, restore, and independent-review evidence is not yet committed.

These findings are a review baseline, not a complete vulnerability list.
