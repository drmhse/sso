# AuthOS project status

AuthOS is under active development in the pre-1.0 release series. The project
may be evaluated for integration work and controlled production pilots whose
operators independently validate the features and deployment model they depend
on. It is not presented as a universally production-ready root identity system.

This distinction is deliberate. Identity infrastructure earns trust through
repeatable tests, protocol conformance, secure release engineering, and tested
recovery procedures. The work required to publish that evidence is tracked in
[PRODUCTION_READINESS.md](./PRODUCTION_READINESS.md).

## Current support statement

The labels used here mean:

- **Stable:** covered by a compatibility commitment and published readiness
  evidence.
- **Beta:** implemented and available, but compatibility or readiness evidence
  is not complete.
- **Experimental:** available for evaluation without a support commitment.
- **Unsupported:** not currently offered as a supported AuthOS configuration.

| Area | Current status |
| --- | --- |
| Rust API and database schema | **Beta.** Breaking changes remain possible before 1.0. |
| Organizations, teams, roles, and permissions | **Beta.** Tenant-isolation evidence is being expanded. |
| OAuth 2.0 and OpenID Connect provider | **Beta.** A public third-party conformance report has not yet been published. |
| Social OAuth and upstream OIDC identity providers | **Beta.** Public interoperability results are not yet published. |
| SAML identity-provider SSO | **Beta.** The public interoperability suite is planned. |
| Upstream SAML identity providers | **Unsupported.** Response signature verification is not implemented; processing fails closed. |
| SCIM provisioning | **Beta.** The public client interoperability suite is planned. |
| Password, magic-link, MFA, and passkey journeys | **Beta.** Security abuse-case evidence is being expanded. |
| OAuth device flow and enterprise-managed authorization | **Beta.** Public end-to-end and abuse-case evidence is incomplete. |
| Service credentials, webhooks, and audit export | **Beta.** Compatibility and delivery/replay evidence is being expanded. |
| Custom domains, branding, and upstream domain routing | **Beta.** Deployment and interoperability boundaries are not yet fully published. |
| Metrics, structured logs, and operational jobs | **Beta.** Dashboard, alert, redaction, and failure-exercise evidence is incomplete. |
| Application secret encryption | **Beta.** A valid 32-byte `ENCRYPTION_KEY` is required for normal startup and managed installers generate it. Legacy plaintext inventory/migration and online key rotation remain incomplete. |
| TypeScript, React, Vue, Node, and CLI packages | **Beta.** Published in the pre-1.0 series; consumers should pin versions. |
| SQLite standalone bundles on Linux amd64/arm64 | **Beta, single-node.** `v0.8.2` publishes SHA-256 checksums, but its installer predates automatic verification. The hardened installer and attestations apply only after a later release completes the new workflow. No multi-writer or HA guarantee is made. |
| PostgreSQL Docker deployments | **Beta.** Backend-specific images are published; an exact server-version support window and runtime compatibility matrix are not yet published. |
| MySQL Docker deployments | **Beta.** Backend-specific images are published; an exact server-version support window and runtime compatibility matrix are not yet published. |
| Multi-node/high-availability operation | **Unsupported as a general guarantee.** HA behavior and topology constraints have not yet been evidenced publicly. |
| Independent security assessment | **Not yet evidenced.** No independent audit report has been published. |
| Upgrade, rollback, and recovery guarantees | **Not yet stable.** Procedures and automated evidence are being formalized. |

## Versioning expectations

- Pre-1.0 releases may contain breaking API, configuration, SDK, or migration
  changes. Changes must be called out in release notes.
- Production users should pin an exact AuthOS version and test upgrades in a
  representative environment.
- Security fixes may require upgrading to the latest release in the current
  series.
- A 1.0 release will not be declared solely because the feature set is broad.
  It must satisfy the evidence gates in the production-readiness plan.

## Choosing AuthOS today

AuthOS can be evaluated when an application needs native organizations,
enterprise federation, provisioning, and application SDKs in a self-hosted
platform. Operators considering AuthOS for critical workloads should review the
limitations above, the [security policy](./SECURITY.md), and the
production-readiness plan before deployment.

Questions about deployment suitability can be raised using the channels in
[SUPPORT.md](./SUPPORT.md). Security-sensitive questions must follow
[SECURITY.md](./SECURITY.md) instead of being posted publicly.
