# Compatibility and deprecation policy

This policy defines how AuthOS classifies compatibility changes. It does not
promote a pre-1.0 capability to stable or expand the support boundary in
[PROJECT_STATUS.md](../../PROJECT_STATUS.md).

## Current pre-1.0 contract

Only the latest published release receives routine security support. Operators
must pin exact versions, back up state, and exercise upgrades against a
representative copy of their deployment. Pre-1.0 releases may contain breaking
changes, but every known breaking, migration, configuration, token, webhook,
or SDK change must be identified in the changelog and release notes.

AuthOS does not currently promise downgrade compatibility. Database migrations
are forward operations unless a release-specific rollback procedure has been
tested and published.

## Compatibility surfaces

Release review must classify changes to each affected surface:

| Surface | Compatibility questions |
| --- | --- |
| HTTP API | Do routes, methods, status codes, request fields, response fields, pagination, or error bodies change? |
| OAuth, OIDC, SAML, SCIM, WebAuthn | Do protocol profiles, metadata, claims, scopes, signatures, identifiers, lifetimes, or validation rules change? |
| Configuration | Are environment variables, defaults, required secrets, accepted formats, ports, paths, or proxy assumptions changed? |
| Database | Are migrations forward-only, data-preserving, restartable, and compatible with the supported source versions? |
| Tokens and sessions | Do issuer, audience, type, claims, signing keys, expiry, rotation, revocation, or cookie behavior change? |
| Webhooks and audit events | Do event names, payload fields, ordering, delivery, retry, or signing behavior change? |
| SDKs and packages | Do exported symbols, types, runtime requirements, package entry points, peer dependencies, or framework versions change? |
| Deployment artifacts | Do platforms, architectures, database variants, image contents, filesystem ownership, health probes, or startup behavior change? |

Adding a response field is not automatically safe: strict clients, signed
payloads, generated types, and protocol schemas must be considered. Tightening
security validation may be necessary in a patch, but its operator impact must
still be documented.

## Change classification

Before 1.0, the release checklist records each affected surface as:

- **compatible** — existing supported behavior continues unchanged;
- **additive** — new optional behavior does not invalidate existing use;
- **breaking** — an existing integration or deployment must change;
- **migration required** — persisted data or configuration must be transformed;
- **security override** — compatibility is intentionally broken to close a
  vulnerability; or
- **not applicable**.

After 1.0, semantic-versioning rules become binding for surfaces explicitly
marked stable. Experimental, Beta, and unsupported surfaces retain the
constraints stated in the maturity matrix. The exact stable deprecation window
and maintained patch-branch schedule must be approved before 1.0; this document
does not invent them in advance.

## Deprecation requirements

A deprecation must identify:

1. the affected surface and first deprecated version;
2. the replacement or migration path;
3. observable warnings that do not disclose secrets;
4. the earliest removal version, if one is approved;
5. schema, token, SDK, and deployment consequences; and
6. a test proving both the deprecated and replacement paths during the overlap.

Removal cannot rely only on elapsed time. The release record must show that the
published replacement works and that the removal follows the support promise
that applied when the deprecation was announced.

## Database and upgrade compatibility

Each release with migrations must publish:

- the source versions exercised on SQLite, PostgreSQL, and MySQL;
- migration ordering, restart behavior, and irreversible boundaries;
- backup and restore prerequisites;
- whether the previous binary can run after migration; and
- the tested rollback or forward-fix procedure.

An untested downgrade must be described as unsupported. A failed migration may
not be treated as successful merely because the process can restart.

## Support and end of life

The current version-support table lives in [SECURITY.md](../../SECURITY.md).
When a maintained-version window or end-of-life date is introduced, release
notes must identify the first and last supported versions, security-fix policy,
upgrade destination, and effective date. Silent end-of-life changes are not
permitted.

## Exceptions

An emergency security fix may intentionally break compatibility when preserving
the old behavior would leave users exposed. The release must identify the risk,
affected versions, required operator action, and why a compatible mitigation
was not safe. Follow the
[emergency-release procedure](./emergency-release.md).
