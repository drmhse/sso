# Changelog

This file records notable user-facing and project-level changes to AuthOS. The
project is pre-1.0; breaking changes are called out explicitly when known.

## [Unreleased]

### Added

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
- A release/versioning lifecycle, public-claim audit, and automated metadata
  consistency check.
- Explicit disclosure of first-party paths that still require a maintainer
  licensing decision.
- SHA-256 verification of standalone release archives before installation.

### Changed

- The README now links to the project's maturity and trust documentation.

### Security

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
- Startup logging no longer prints database connection URLs that may contain
  PostgreSQL or MySQL credentials.
- OAuth token response bodies, access-token hashes, and registration email
  addresses are no longer written to application logs.
- Bootstrap-generated deployments now pin the current `v0.8.2` Docker image
  variants instead of the stale `v0.1.51` variants.
- Access-token validation now requires issuer and audience claims, enforces the
  configured issuer, rejects external-resource tokens at AuthOS management
  endpoints, and enforces the requested resource audience during token exchange.
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

## 0.8.2 - 2026-06-20

- Published coordinated AuthOS packages using the release tag version.
- Published standalone SQLite bundles for Linux amd64 and arm64 with SHA-256
  checksums.
- Published backend-specific, multi-architecture Docker images through the
  release workflow.

Earlier pre-1.0 history is available from
[GitHub Releases](https://github.com/drmhse/AuthOS/releases).

[Unreleased]: https://github.com/drmhse/AuthOS/compare/v0.8.2...HEAD
