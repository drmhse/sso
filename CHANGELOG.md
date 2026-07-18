# Changelog

This file records notable user-facing and project-level changes to AuthOS. The
project is pre-1.0; breaking changes are called out explicitly when known.

## [Unreleased]

No changes yet.

## 0.8.4 - 2026-07-18

### Changed

- The coordinated npm reusable-workflow caller now supplies the permission
  ceiling required to validate its publication job. Artifact preparation and
  source qualification remain explicitly read-only inside the called workflow.

## 0.8.3 - 2026-07-18

### Added

- Regression coverage for device-code expiry cleanup and a 30-minute budget-VM
  qualification case that crosses both code expiry and cleanup intervals.
- A CI-enforced, explicitly partial tenant-isolation matrix covering every
  current SeaORM entity and route path, with named SQLite evidence and
  categorized critical/high gaps.
- Cross-tenant unchanged-state regressions for billing credentials and
  webhooks, service identities and API keys, organization sessions,
  audit/billing capabilities, and platform/service authority.
- Pull-request CI for Rust quality, database-feature compilation, and
  TypeScript checks, tests, and builds.
- Dependency review, npm and Rust advisory audits, CodeQL analysis, and
  Dependabot update configuration.
- Release qualification for the exact annotated tag, SPDX SBOM generation,
  checksums, keyless artifact attestations, and container provenance.
- Manual npm workflow dispatches are dry-run-only; real publication requires a
  qualified annotated release tag.
- Public security, support, contribution, and project-status policies.
- An evidence-based production-readiness plan with explicit `v0.9` and `v1.0`
  gates.
- A release/versioning lifecycle and automated metadata consistency check.
- An online SQLite backup helper with restrictive output permissions,
  integrity and SHA-256 verification, overwrite protection, and a concurrent
  write regression.
- PostgreSQL 16 and MySQL 8.4 CI logical backup/restore qualification that
  preserves an existing login and tenant, then exercises new post-restore CRUD
  with the original protected key material.
- Exact npm publish tarballs, per-package SPDX SBOMs, SHA-256 manifests, GitHub
  artifact/SBOM attestations, and retention-aware verification instructions.
- Exact npm tarballs, SBOMs, checksums, and a source-bound package manifest are
  also attached to the GitHub release, with a clean verifier for package
  identity, version, digest, SPDX, and tar safety.
- Explicit disclosure of first-party paths that still require a maintainer
  licensing decision.
- SHA-256 verification of standalone release archives before installation.
- A machine-readable standalone release manifest binding the release tag, full
  source commit, workflow run, payload digests, and archive-to-SBOM mappings;
  the clean-environment verifier checks it before accepting the release set.
- Attested, release-attached container records for SQLite, PostgreSQL, and
  MySQL bind each multi-platform image digest to its release tag, source commit,
  workflow run, and registry SBOM/provenance expectations.

### Changed

- `DISABLE_RATE_LIMITING=true` now removes the route-level governors as its
  name states, keeping it suitable for isolated tests and benchmarks only.
- AuthOS Compose deployments now set the API container's open-file limit to
  65,535, matching the standalone systemd service and benchmark runner.
- Billing subscription webhooks now bind customer, organization, service,
  plan, and user membership; service-principal identity access binds both
  organization and service; inactive tenant service keys are denied; platform
  demotion is checked against current database state.
- Tenant administration now scopes plan, SCIM-token, domain-route,
  upstream-provider, and SIEM mutations by both parent and child identifiers;
  suspended tenants are denied across service, risk, integration, billing,
  webhook, and audit surfaces, including background webhook polling. Audit
  filter totals and target pagination now match the tenant-scoped query.
- Tenant login and risk analytics now combine explicit organization scope with
  compatible legacy service-derived scope, include legitimate service-less
  tenant events, and reject inconsistent organization/service pairs. Recent
  login responses represent a missing service explicitly.
- Invitation acceptance now claims pending state before side effects and
  requires a currently active parent; suspended tenants cannot create users or
  memberships through outstanding invitations. Invitation list responses no
  longer expose stored token verifiers.
- Conventional SQL-backed list endpoints now normalize non-positive limits to
  a one-item minimum and negative offsets to zero before unsigned conversion.
  SCIM retains RFC-compatible `count=0` behavior, and the organization service
  list retains its established in-memory `limit=0` empty-page behavior.
- The README now links to the project's maturity and trust documentation.
- Checked-in operator Compose topologies now align all AuthOS images with
  `v0.8.3` and the release-qualified PostgreSQL 16/MySQL 8.4 engines; the trust
  gate rejects stale or unclassified Compose pins.

### Security

- Rate-limit keys and request auditing now share one trusted-proxy-aware client
  IP resolver. Forwarding headers are accepted only from an explicitly
  allowlisted socket peer; direct clients cannot rotate spoofed headers to
  evade per-IP limits.
- Branding and custom-domain authorization now rechecks live platform-owner
  authority and active tenant state at request and transaction boundaries;
  OAuth callback/session completion similarly revalidates exact active
  organization, service, redirect, resource, and current user entitlement.
- SCIM deactivation and deletion now atomically revoke only the selected
  organization's memberships, permissions, sessions, identities, grants,
  provider requests, pending OAuth/SAML/device state, and enqueue the matching
  durable audit event while preserving other-organization and platform state.
- Provider token refresh jobs re-read live user/tenant/service authority before
  outbound I/O and use conditional transactional writeback so revocation,
  suspension, or token replacement wins. Email verification and password reset
  now commit one-time consumption with account mutation and session revocation
  in a single transaction.

- Application-secret writes now use AES-GCM V2 envelopes authenticated to the
  physical table, record ID, and field. The bounded `rewrap-secrets` command
  migrates legacy/V1, SIEM, webhook, identity, and connected-account values
  with compare-and-swap updates; webhook/SIEM runtime plaintext fallback is
  rejected. SQLite covers context swapping, migration, resume, and tampering.
- SIEM connection tests decrypt only the credential selected by the provider,
  require authentication for named providers, reject unsafe custom headers,
  bound downstream response bodies, and do not reflect downstream bodies or
  transport errors. Audit metadata redaction now covers nested credential keys
  with value suffixes and common passphrase/credential/recovery-code names
  while retaining explicitly non-secret identifiers and descriptors.
- JWT signing-key rotation now supports one active signing key plus an optional
  previous public-key ring keyed by `kid`. Validators accept only configured
  active/previous keys, issuance always uses the active key, and JWKS publishes
  the complete verification set for an overlap window. Unknown, retired,
  mismapped, duplicated, and malformed key configurations fail closed.

- Upgraded `quick-xml` to 0.41 and adapted SAML parsing to remediate
  `RUSTSEC-2026-0194` and `RUSTSEC-2026-0195` denial-of-service issues. Added
  regression coverage for escaped XML values, malformed XML/attributes,
  invalid roots, and external or unknown entity references.
- SAML Redirect decoding now accepts standards-shaped raw-DEFLATE requests
  without requiring an XML declaration, rejects encoded requests above 256 KiB,
  and caps expanded or POST-binding XML at 1 MiB. Metadata, assertion, response,
  and logout XML now structurally escapes configurable, request, and user values;
  canonicalization fails closed on malformed XML instead of signing partial output.
- Updated vulnerable or unsound Rust dependencies including `anyhow`,
  `crossbeam-epoch`, and the inactive `quinn-proto` lockfile entry.
- Updated transitive npm dependencies `undici` and `js-yaml`; `npm audit`
  reports no known vulnerabilities at the current development baseline.
- The standalone installer now verifies its selected archive against the
  release checksum manifest before extraction.
- Standalone archive extraction now rejects non-HTTPS redirects, oversized or
  non-exact checksum inputs, traversal, links, special files, duplicate
  members, unexpected inventory, and expansion/member-limit violations. API
  key output is confined beneath managed data using no-follow directory file
  descriptors, atomic replacement, and parent/target race checks; installed
  license, AGPL, and exact source-offer notices are retained atomically.
- Startup logging no longer prints database connection URLs that may contain
  PostgreSQL or MySQL credentials.
- OAuth token response bodies, access-token hashes, and registration email
  addresses are no longer written to application logs.
- Bootstrap-generated deployments now pin the current `v0.8.3` Docker image
  variants instead of the stale `v0.1.51` variants.
- Access-token validation now requires issuer and audience claims, enforces the
  configured issuer, rejects external-resource tokens at AuthOS management
  endpoints, and enforces the requested resource audience during token exchange.
- AuthOS-signed management, external-resource, MFA pre-authentication,
  impersonation, and ID-JAG tokens now carry distinct JOSE `typ` headers and a
  signed `token_use`; validators enforce the exact profile, issuer, audience,
  algorithm, configured key ID, and actor/MFA invariants. This is a breaking
  pre-1.0 session boundary: JWTs issued by earlier builds lack the required
  profile fields and users must reauthenticate after upgrading.
- Session refresh tokens are now 256-bit opaque values stored only as SHA-256
  hashes. Rotation atomically records consumed ancestors, and reuse revokes the
  entire session family. The migration clears legacy plaintext refresh values,
  so existing refresh sessions must reauthenticate after upgrading; a downgrade
  cannot reconstruct those cleared bearer values.
- `/metrics` is disabled by default and requires a configured bearer token when
  enabled; token digests are compared in constant time.
- A configurable global streaming request-body limit now rejects oversized
  requests with HTTP 413 and defaults to 1 MiB.
- Added SQLite tenant-isolation regressions for webhook listing, event
  selection, updates, and deletion, including cross-organization and missing-ID
  denial with unchanged-state assertions.
- Normal API startup now fails closed before database initialization unless
  `ENCRYPTION_KEY` is exactly 64 hexadecimal characters. A narrowly named
  development/test-only escape hatch permits a missing key for disposable data;
  it does not relax malformed-key validation or migrate legacy plaintext rows.
- Device-trust token signing now rejects a missing, malformed, or incorrectly
  sized `DEVICE_TRUST_SECRET` instead of silently using an all-zero production
  fallback. Managed installers continue to generate 32 bytes of hexadecimal
  key material.
- Release containers now run as UID/GID `10001`, keep application files
  non-writable, restrict new SQLite files to the service account, and ship a
  readiness health check. Generated Compose deployments also use a read-only
  root filesystem, a bounded `noexec` temporary directory, no Linux
  capabilities, and `no-new-privileges`.
- OAuth provider-token refresh now validates and pins resolved destinations,
  rejects additional special-purpose IPv4 and IPv4-mapped IPv6 ranges, disables
  redirects, bounds response bodies at 64 KiB, and avoids returning raw remote
  response bodies in errors.
- GitHub, Google, and Microsoft user-info requests now use the same pinned DNS,
  no-redirect SSRF policy and a 64 KiB response limit; provider error bodies and
  malformed profile data are not reflected to clients.
- GeoIP database setup now validates and pins both download destinations,
  permits only MaxMind's documented HTTPS R2 redirect without forwarding the
  license key, bounds compressed and expanded archive work, and atomically
  installs the bounded database file with restrictive permissions.
- Security audit events now use a database-backed durable outbox with bounded,
  idempotent reconciliation, retry/dead-letter state, and all four login,
  organization, MFA, and platform event kinds. High-risk API-key, membership,
  role/ownership, service-access, billing-credential, and impersonation
  mutations commit or roll back with their success event.
- Authentication, invitation, impersonation, organization-switch, cleanup, and
  bootstrap tracing now attributes events with opaque IDs instead of email
  addresses. CI rejects credential and email values passed to tracing macros
  and exercises a failing negative-control fixture.
- File-backed SQLite race regressions now prove single-winner consumption for
  password-reset tokens, magic links, OAuth callback state, and authorized
  client-bound device codes; a losing or wrong-client exchange cannot reuse the
  one-time value.
- OAuth and upstream-SAML callback handlers now require winning the atomic
  state deletion before they process a callback; concurrent losers fail closed,
  and OAuth callbacks reject missing or empty state.
- Bootstrap-login tokens now use constant-time comparison and a database-backed
  consumption record so concurrent processes have one winner before the managed
  state file records use. Missing expiry is rejected.
- Impersonation tokens now require a live revocable session. Each request
  bypasses identity/permission caches and rechecks the actor's current platform
  authority or tenant admin role, organization status, and target membership;
  reasons are mandatory and bounded, and nested impersonation is rejected.
- Email verification uses an expiry-aware conditional claim, and WebAuthn
  challenge deletion has explicit concurrent one-winner coverage. Successful
  WebAuthn authentication now persists the complete library-updated credential,
  counter, and backup state with optimistic concurrency so stale ceremonies
  cannot overwrite newer authenticator state.
- MFA device pre-authentication tokens now sign the exact device-code context;
  verification rejects missing, injected, or mismatched context before checking
  the MFA secret, and authorization still requires an exact pending, unexpired,
  user-bound row.
- Device authorization now atomically claims an unexpired pending row, prevents
  stale callbacks from replacing its principal, and permits token exchange
  after the browser has completed the bound MFA transition.
- SAML RSA certificate generation now runs off the async executor behind a
  bounded semaphore, uses unique random serial numbers, and encodes the same
  three-year validity period stored by AuthOS. Signing uses one active key while
  metadata publishes a bounded seven-day overlap, with explicit retirement,
  expiry status, deletion cleanup, and concurrent-rotation controls.
- Added CI-checked starter Prometheus recording/alert rules and a Grafana
  operations dashboard with a linked alert-response and drill procedure; the
  thresholds remain explicitly unqualified until measured failure exercises.
- Assigned AGPL-3.0-only to the lite web client, scripts, and installer, added
  a CI-enforced first-party license policy, and included the applicable license
  notices in standalone release bundles.
- Cross-version publication is serialized, prerelease tags are rejected until
  an isolated dist-tag policy exists, and every immutable and mutable Docker
  tag is verified against its prepared digest before a GitHub release becomes
  public. npm tarballs and OCI images now carry their complete license notices.

## 0.8.2 - 2026-06-20

- Published coordinated AuthOS packages using the release tag version.
- Published standalone SQLite bundles for Linux amd64 and arm64 with SHA-256
  checksums.
- Published backend-specific, multi-architecture Docker images through the
  release workflow.

Earlier pre-1.0 history is available from
[GitHub Releases](https://github.com/drmhse/AuthOS/releases).

[Unreleased]: https://github.com/drmhse/AuthOS/compare/v0.8.4...HEAD
[0.8.4]: https://github.com/drmhse/AuthOS/compare/v0.8.3...v0.8.4
[0.8.3]: https://github.com/drmhse/AuthOS/compare/v0.8.2...v0.8.3
