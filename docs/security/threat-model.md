# AuthOS threat model

Status: source-review baseline, not an independent assessment

Reviewed: 2026-07-14

Scope: the Rust API, its database records, background jobs, embedded web routes,
and first-party protocol endpoints in this repository

## How to read this document

This model records what the current source shows and what still requires proof.
It is not a security certification, conformance statement, penetration-test
result, or deployment guarantee. A control marked **source-evidenced** has an
identifiable implementation in the paths cited below; it has not necessarily
been tested end to end or assessed independently. **Partial** means the source
implements part of the control. **Unverified** means the review did not find
enough evidence to make the claim. **Gap** means the source exposes an explicit
missing control or a security-relevant design limitation.

The associated [security architecture](./security-architecture.md) describes
the implemented mechanisms. The
[tenant-resource inventory](./tenant-resource-inventory.md) defines the data
surface that isolation tests must cover.

## Security objectives

AuthOS is intended to preserve these properties:

1. A tenant user, tenant administrator, service principal, or provisioning
   client cannot read or mutate another organization's data.
2. A user cannot authenticate as another user, reuse a one-time credential, or
   extend a session beyond its documented lifetime.
3. Platform-owner authority is distinct from organization and service
   authority and cannot be obtained from tenant-controlled input.
4. OAuth/OIDC, SAML, SCIM, passkey, MFA, password, magic-link, and recovery
   flows bind responses to the initiating actor, client, tenant, destination,
   and transaction.
5. Passwords, signing keys, bearer credentials, provider credentials, and
   recovery material are not disclosed through storage, logs, APIs, or release
   artifacts.
6. Security-relevant actions remain attributable, while audit and telemetry do
   not become a second path for credential or personal-data disclosure.
7. Untrusted outbound destinations cannot use AuthOS to reach loopback,
   private, link-local, metadata, or otherwise reserved networks.
8. Operators can rotate or revoke credentials, recover data, and investigate
   incidents without relying on undocumented behavior.

Objectives 1 through 7 have implementation fragments in the repository, but
none should be treated as fully proven until the evidence requirements below
are satisfied. Objective 8 remains primarily an operational-readiness item.

## Assets

| Asset | Why it matters |
| --- | --- |
| User accounts, emails, identities, memberships, roles, and permissions | Control identity and tenant authority. |
| Password hashes, TOTP secrets, backup-code hashes, passkeys, reset links, magic links, and device credentials | Enable authentication or recovery. |
| Access tokens, refresh tokens, sessions, OAuth state, authorization grants, device codes, SAML state, and WebAuthn challenges | Bind and continue authentication transactions. |
| JWT private key and SAML signing private keys | Let a holder mint trusted assertions. |
| Organization OAuth, upstream-provider, billing, SMTP, SIEM, webhook, and service credentials | Authorize access to AuthOS or external systems. |
| Organization configuration, services, plans, subscriptions, domains, branding, webhooks, and provisioning state | Tenant data and security policy. |
| Organization, login, MFA, and platform audit data | Supports detection, attribution, and incident response. |
| Database contents, migrations, backups, environment variables, binaries, images, and installer artifacts | Define the integrity and recoverability of the system. |

## Actors and capabilities

| Actor | Expected authority | Adversarial cases |
| --- | --- | --- |
| Unauthenticated internet client | Public discovery, branding, authentication initiation, callbacks, health routes, and public protocol routes | Enumeration, credential stuffing, replay, parser abuse, resource exhaustion, malicious redirect/state input. |
| End user | Own profile, credentials, devices, sessions, linked accounts, and memberships granted to the user | Horizontal access to another user or tenant; recovery or linking abuse. |
| Organization member/admin/owner or custom role | Tenant resources permitted by membership/relationship tuples | Cross-tenant access, role escalation, confused-deputy requests using path IDs. |
| Platform owner | Platform governance and explicitly protected administrative operations | Account compromise, unsafe impersonation, abuse of bootstrap configuration. |
| Service principal | Service API operations allowed by an API key's permission list | Stolen key, permission bypass, access to another service or organization. |
| SCIM client | Provisioning operations for the organization bound to its token | Stolen token, forged organization header, cross-tenant resource IDs. |
| OAuth/OIDC or SAML identity provider | Supplies external identity assertions and tokens | Malicious/compromised provider, issuer confusion, unsigned or replayed response. |
| Service provider / relying party | Initiates OAuth/OIDC or SAML requests and consumes assertions | Redirect/ACS substitution, malicious client registration, assertion replay. |
| Email, billing, SIEM, webhook, DNS, GeoIP, and database dependencies | Deliver configured infrastructure functions | Dependency outage, malicious response, SSRF target, data exfiltration, stale data. |
| Host, database, and reverse-proxy operator | Controls deployment, secrets, storage, network, and process lifecycle | Misconfiguration or compromise; this actor is inside the deployment trust base. |
| Supply-chain participant | Contributes dependencies, CI workflows, images, and release inputs | Dependency compromise, workflow injection, artifact substitution. |

## Trust boundaries

1. **Internet to reverse proxy/API.** The application listens on a configured
   host/port. TLS termination and proxy correctness are deployment controls,
   not established by the Rust process. Proxy-derived client IPs are used only
   when `TRUST_PROXY_HEADERS` is enabled and the socket peer is listed in
   `TRUSTED_PROXY_IPS` (`api/src/middleware.rs`).
2. **Browser to public/authenticated routes.** Dynamic CORS checks platform and
   API origins, verified active custom domains, and registered service redirect
   origins. Local/private development origins receive an explicit exception
   (`api/src/middleware.rs`). CORS is not an authorization boundary.
3. **Bearer token to authenticated user.** RS256 verification and expiration
   checks are followed by a database lookup for a non-expired session on
   ordinary access-token requests (`api/src/auth/jwt.rs`,
   `api/src/middleware.rs`, `api/src/store/sessions.rs`).
4. **User to organization/service.** Organization membership, built-in roles,
   relationship tuples, and resource-specific checks are performed in handlers
   and stores. The reviewed schema uses a shared database; no database
   row-level-security policy was found. Tenant isolation therefore depends on
   complete application query scoping.
5. **API/SCIM key to service/organization.** API keys resolve to one service;
   SCIM tokens resolve to one organization. Both are stored as hashes and
   checked by route middleware (`api/src/auth/api_key.rs`,
   `api/src/middleware.rs`, `api/src/store/scim_tokens.rs`).
6. **AuthOS to external endpoints.** Webhook, SIEM, and configurable OAuth/OIDC
   paths use `SafeHttpClient` in the reviewed call sites. It resolves and pins
   public addresses and disables redirects (`api/src/services/safe_http.rs`).
   Not every direct `reqwest` use has been proven to share that policy.
7. **Process to database and secret material.** The database stores identity,
   tenant, session, and audit records. Normal API startup requires one valid
   environment-provided `ENCRYPTION_KEY`, used with AES-256-GCM for selected
   secrets. Only the explicit `AUTHOS_ALLOW_UNENCRYPTED_DEVELOPMENT=true`
   escape hatch permits a missing key, and it is unsafe for persistent data;
   JWT signing keys are supplied as environment variables
   (`api/src/encryption/mod.rs`, `api/src/main.rs`).
8. **Foreground request to background work.** Email, webhook, refresh, cleanup,
   metrics, and audit work crosses asynchronous queues/tasks. Delivery,
   idempotency, shutdown, and failure handling require separate evidence.

## Major flows and threat decisions

### Password, recovery, magic-link, MFA, and passkey flows

- Passwords and MFA backup codes use Argon2 with per-secret salts
  (`api/src/handlers/auth/password.rs`, `api/src/auth/mfa.rs`). Password login
  performs a dummy Argon2 verification for unknown/passwordless users to reduce
  a timing distinction. This is **source-evidenced**, not a measured
  enumeration-resistance result.
- Password reset, email verification, and magic-link values are stored as
  SHA-256 hashes with expirations. Reset consumption performs a conditional
  one-time update; magic-link and WebAuthn challenge consumption delete the
  record and check affected rows (`api/src/store/password_reset.rs`,
  `api/src/store/magic_links.rs`, `api/src/store/webauthn_challenges.rs`).
- MFA pre-authentication tokens expire after five minutes. Consumption uses a
  distributed lock keyed by JWT `jti` (`api/src/auth/jwt.rs`,
  `api/src/handlers/auth/mfa.rs`). Multi-node replay behavior is **unverified**.
- WebAuthn uses `webauthn-rs`, binds the RP to a domain-backed HTTPS
  `BASE_URL` (or localhost), stores five-minute ceremony state, checks the
  registering user, consumes challenges, and updates credential counters
  (`api/src/main.rs`, `api/src/services/webauthn.rs`,
  `api/src/handlers/auth/passkeys.rs`). Full origin/RP, cloned-authenticator,
  and concurrent-consumption tests remain required.

### Sessions and tokens

- Access tokens are RS256 JWTs. Ordinary authenticated requests also require a
  non-expired session matching the token's SHA-256 hash, enabling session
  deletion to revoke access (`api/src/auth/jwt.rs`, `api/src/middleware.rs`).
- Refresh tokens rotate through a conditional database update so simultaneous
  reuse should leave one winner (`api/src/handlers/auth/session.rs`,
  `api/src/store/sessions.rs`). Refresh tokens are stored in plaintext in the
  current session entity. Storage hardening and replay-family handling are
  **gaps**.
- Ordinary access-token validation now requires `exp`, `iss`, and `aud`, fixes
  the algorithm to RS256, and compares `iss` to the configured issuer. AuthOS
  management routes additionally require the audience derived from the token's
  platform, organization, service, or impersonation profile; resource-scoped
  tokens are rejected there. OAuth token exchange validates the exact requested
  resource audience (`api/src/auth/jwt.rs`, `api/src/middleware.rs`,
  `api/src/handlers/auth/enterprise.rs`). External resource servers must still
  validate their own configured audience, and broader cross-profile confusion
  and token-type testing remains a **gap**.
- JWKS publishes one configured RSA public key and `kid`. No overlapping
  verification-key set or tested rollover procedure is implemented in the
  reviewed path (`api/src/main.rs`).

### OAuth/OIDC and device flows

- OAuth state is persisted with an expiration and flow context; callbacks load
  and delete it before token exchange. PKCE is generated for upstream flows and
  enforced for public service types (`api/src/handlers/auth/oauth.rs`,
  `api/src/store/oauth_states.rs`). Concurrency and all error branches require
  replay tests.
- Registered service redirect URIs are revalidated before service redirects in
  reviewed callback paths. A complete open-redirect inventory remains
  **unverified** because several flows construct return locations.
- Device codes have separate rate limits and database state
  (`api/src/router.rs`, `api/src/store/device_codes.rs`). Polling interval,
  binding, expiry, and concurrent exchange require end-to-end evidence.
- No public OpenID/OAuth conformance result is committed. Discovery metadata,
  claims, grant behavior, client authentication, revocation, and error semantics
  must be treated as **unverified for conformance**.

### SAML

- The IdP path checks organization status, service ownership/configuration,
  configured ACS URL, request destination when present, and request issuer. It
  rejects DTD declarations, unknown entity references, malformed XML and
  attributes, invalid request roots, encoded requests over 262,144 bytes, and
  decoded request XML over 1,048,576 bytes; it also creates expiring SAML state.
  Raw-DEFLATE Redirect requests do not require an XML declaration. Generated
  metadata, assertion, response, and logout XML structurally escapes request,
  configuration, and user values, and canonicalization rejects malformed input.
  Focused regressions cover those boundaries. Assertions include time conditions
  and may be signed with encrypted per-service keys (`api/src/handlers/saml.rs`).
- The reviewed IdP AuthnRequest path does not verify a request signature. The
  XML-signature construction is custom and has no committed interoperability or
  signature-wrapping test evidence. These are **unverified controls**.
- Upstream SAML response processing explicitly returns an error because
  signature verification is not implemented
  (`api/src/handlers/auth/upstream_saml.rs`). This is a fail-closed **gap** and
  upstream SAML must not be represented as operational until it is implemented
  and tested.

### SCIM, service APIs, and tenant administration

- SCIM middleware binds a hashed, active, unexpired bearer token to its stored
  organization and rejects a conflicting optional `X-Organization-ID` header.
  SCIM user handlers additionally check organization membership; group handlers
  bind the only represented group to the token organization
  (`api/src/middleware.rs`, `api/src/handlers/scim/`).
- Service API middleware resolves a hashed API key by prefix, performs a
  constant-time hash comparison, checks expiration, and supplies the bound
  service plus serialized permissions (`api/src/auth/api_key.rs`,
  `api/src/middleware.rs`). Every service handler still needs a negative test
  proving its permission and resource binding.
- Tenant administration handlers generally resolve an organization from the
  path and then require membership, built-in role, or a relationship-tuple
  capability. The inventory records the full surface. Because enforcement is
  distributed across handlers and stores, comprehensive negative tests are a
  release requirement rather than an inferred guarantee.

## Prioritized abuse cases

| Priority | Abuse case | Current control/evidence | Required disposition |
| --- | --- | --- | --- |
| Critical | Forge or accept an upstream SAML assertion | Processing fails closed; verification is explicitly unimplemented. | Keep feature unavailable; implement standards-based signature, issuer, audience, destination, time, `InResponseTo`, and replay validation before advertising support. |
| Critical | Tenant A supplies Tenant B's resource ID | Application-level org/service/user filters and handler checks exist; no DB RLS was found. | Automated deny tests for every inventory row and every ID-bearing CRUD route on all databases. |
| High | Reuse or redirect an OAuth transaction | Expiring stored state, callback deletion, PKCE, and redirect checks exist in reviewed paths. | Concurrent replay, missing/mismatched state, PKCE downgrade, every redirect sink, and authorization-code reuse tests. |
| High | Use a valid JWT in the wrong issuer/audience context | RS256, expiry, configured issuer, required audience, AuthOS API audience profiles, and token-exchange resource audience are enforced. | Enforce the configured resource audience at every external resource server; add explicit token types and a complete cross-profile confusion suite. |
| High | Steal database contents and replay refresh/external credentials | Normal startup now fails closed without the application encryption key. Selected secrets are encrypted or hashed; refresh tokens, webhook secrets, SIEM API data, and legacy connected-account plaintext columns remain. | Remove plaintext storage paths, migrate existing data, rotate affected secrets, and test redaction/backups. |
| High | Replay MFA, magic-link, reset, or WebAuthn state concurrently | Conditional update/delete and expirations exist; MFA uses a distributed lock. | Multi-request and multi-replica atomicity tests for every one-time value. |
| High | Abuse platform-owner bootstrap or impersonation | Platform routes require current DB `is_platform_owner`; impersonation is 15 minutes and carries an actor claim. | Bootstrap lifecycle, MFA policy, session/revocation, target-scope, audit completeness, and non-escalation tests. |
| High | Redirect a webhook/SIEM/OIDC request to metadata or an internal host | Safe client rejects private/reserved resolutions, pins DNS results, and disables redirects in reviewed paths. | Enumerate every outbound call, enforce one client/policy, and test IPv4/IPv6 encodings, DNS rebinding, proxy use, and redirect chains. |
| Medium | Evade rate limits behind spoofed proxy headers or across replicas | Trusted-proxy allowlist exists; route limiters are process-local. | Deployment tests for proxy topology and distributed/rate-limit behavior across replicas; document failover/reset semantics. |
| Medium | Exfiltrate through operational metrics or logs | Metrics use bounded labels; `/metrics` is disabled without a configured token and otherwise requires a constant-time bearer-token check. No complete redaction evidence exists. | Also network-restrict metrics, define allowed fields, and run log/audit/trace secret canaries. |
| Medium | Exhaust CPU/memory with crypto, XML, JSON, request bodies, or high-cardinality input | Route rate limits, a 30-second timeout, and a configurable global streaming body limit (1 MiB default) exist. | Add decompression/XML limits, crypto concurrency limits, fuzzing, and broader resource-exhaustion tests. |
| Medium | Lose or silently omit security audit events | Buffered audit inserts retry and flush on graceful shutdown, but code can drop batches after retry exhaustion or when the channel closes. | Define failure semantics, durable delivery requirements, crash tests, alerting, and reconciliation. |

## Deployment assumptions that are not application guarantees

- TLS is correctly terminated, HTTP is redirected to HTTPS, and forwarded
  headers are stripped/replaced by a trusted proxy.
- The database, backups, environment files, process account, and host are
  access-controlled and encrypted according to operator policy.
- JWT and encryption keys are generated securely, stored outside the image and
  repository, backed up safely, and rotated by an operator.
- System clocks, DNS, SMTP, external identity providers, and databases are
  trustworthy enough for the configured deployment.
- `/metrics`, readiness details, and administrative endpoints are restricted at
  the network/proxy layer where required; the metrics bearer token is supplied
  through a secret manager and never through a URL.
- `DISABLE_RATE_LIMITING` is not enabled in production.

These assumptions need deployment validation and runbooks before a production
claim. The application currently cannot prove them.

## Required security evidence

The following evidence is necessary to move controls from source review to a
release claim:

1. A generated authorization matrix covering every resource in the tenant
   inventory, with owner/admin/member/non-member/platform/service/SCIM actors
   and same-tenant/cross-tenant IDs on SQLite, PostgreSQL, and MySQL.
2. OAuth/OIDC conformance output plus negative tests for state, PKCE, code and
   refresh replay, issuer, audience/resource, token type, algorithm, redirect,
   revocation, and signing-key rollover.
3. SAML interoperability and adversarial XML/signature tests. Upstream SAML
   remains unavailable until signed-response validation passes.
4. SCIM client interoperability, filtering/pagination/idempotency tests, and
   cross-tenant CRUD/group tests.
5. Concurrent one-time-token tests for reset, verification, magic link, OAuth,
   SAML, device, MFA, and WebAuthn state.
6. A cryptographic inventory and drill for JWT/SAML/encryption-key rotation,
   compromise, recovery, and overlapping verification windows.
7. Secret-at-rest and redaction tests using canary values across the database,
   backups, logs, errors, audit payloads, metrics, exports, and APIs.
8. Outbound-request inventory and SSRF tests for every caller, including DNS
   changes, IPv6, redirects, proxies, and internal address representations.
9. Fuzzing and bounded-resource tests for XML, SCIM filters, JWTs, request
   bodies, decompression, webhook payloads, and protocol parsers.
10. Independent review of the exact release candidate with a public scope and
    remediation status.

## Maintenance

The Security lead owns this model. Update it when a new route, token type,
tenant-scoped entity, external integration, credential store, cryptographic
primitive, trust boundary, deployment topology, or privileged role is added.
Each release review should link the exact commit and evidence artifacts used to
change any status in this document.
