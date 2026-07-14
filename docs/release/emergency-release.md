# Emergency release and signing-compromise procedure

Use this procedure for a critical vulnerability, actively exploitable defect,
unsafe release artifact, compromised publishing identity, or release-system
failure that requires coordinated containment. It is an operational procedure,
not evidence that an exercise has already passed.

## Roles

Assign an incident lead, security lead, release engineer, and communications
owner. One person may fill multiple roles in a small team, but the final release
requires a second reviewer who did not build the artifacts.

Record decisions and timestamps in a private incident record while disclosure
is coordinated. Never put credentials, exploit data, or personal information in
public CI logs or issues.

## Containment

1. Freeze routine releases and identify the affected versions, commits,
   packages, images, installers, keys, tokens, and environments.
2. Preserve relevant logs and artifact digests without copying live secrets.
3. Revoke or rotate compromised GitHub, npm, Docker, CI, signing, deployment,
   and operator credentials. Review recent audit activity.
4. Disable a vulnerable distribution channel or capability when continued
   availability would cause greater harm.
5. Open a private GitHub security advisory when appropriate and coordinate
   reporter communication under [SECURITY.md](../../SECURITY.md).

Published bytes must never be silently replaced under an existing version or
tag. A corrected artifact receives a new version and provenance chain. If an
artifact is unsafe, mark it revoked or withdrawn wherever the registry permits
and publish its digest so operators can identify it.

## Fix qualification

The release candidate must:

- originate from a reviewed commit reachable from the protected release line;
- include a regression test for the failure where safe;
- pass the normal qualification suite plus tests targeted at the incident;
- document compatibility, migration, rollback, and key-rotation consequences;
- produce fresh checksums, SBOMs, provenance, and attestations; and
- receive Security and Release approval recorded in the
  [release checklist](./release-checklist.md).

If normal checks are unavailable, the incident lead records which checks were
skipped, why, the compensating review, and the deadline for a fully qualified
follow-up. An emergency does not justify reusing compromised credentials.

## Publication and verification

1. Create a new annotated semantic-version tag for the reviewed commit.
2. Allow the standard workflows to publish; do not run an undocumented local
   publishing command.
3. From a clean environment, verify standalone archives, checksums,
   attestations, image digests/provenance, npm tarballs/provenance, embedded
   versions, and installer selection.
4. Confirm registry and release pages identify the intended commit and contain
   no artifact from a failed or compromised build.
5. Publish the advisory and release notes with affected/fixed versions,
   severity, required action, mitigations, compatibility impact, and credit.

## Rollback and recovery

Prefer a forward fix after an irreversible migration. Roll back only when the
exact binary/schema/configuration path has been exercised against a protected
backup. Rotate affected secrets and invalidate sessions or credentials when the
incident scope requires it.

After service is restored, reconcile audit events, jobs, webhook delivery, and
tenant state. Continue monitoring for exploitation and failed upgrades.

### Partial registry publication

npm and Docker registries do not provide a transaction spanning all AuthOS
packages, image variants, tags, and GitHub assets. If publication stops after
any external write:

1. Do not rerun the failed tag and do not publish missing artifacts under its
   version. Preserve the draft release, workflow logs, prepared artifacts, and
   the last successful registry response.
2. Inventory exactly which npm versions, Docker version tags/digests,
   attestations, and release assets became visible. Record the first failure
   and whether any moving `latest` alias changed.
3. Deprecate, withdraw, or clearly mark each partial immutable version as
   failed where the registry permits. Never replace its bytes. A moving alias
   may be restored to its previously recorded known-good digest only through an
   approved incident action; immutable version tags remain untouched.
4. Fix the cause on a reviewed commit, choose a strictly new semantic version,
   and run the complete protected workflow from a new annotated tag. The
   cross-channel preflight must pass before that new version publishes.
5. Link the partial version, new version, affected digests, and operator action
   in the incident record, release notes, and advisory when disclosure is safe.

This new-version-only rule applies even when the missing artifact could be
reconstructed byte-for-byte. It keeps the public version identity and its
failure evidence unambiguous.

Release publication is globally serialized across version tags so two runs
cannot race mutable `latest` aliases. Do not change that concurrency group to a
per-tag value. The current workflow accepts stable `vMAJOR.MINOR.PATCH` tags
only; introduce an isolated npm dist-tag and non-latest container/GitHub policy
before enabling prerelease tags.

## Post-incident evidence

Within the disclosure constraints, retain:

- incident timeline and decision owners;
- affected and fixed artifact digests;
- credential/key revocation evidence;
- regression and qualification results;
- clean-environment verification transcript;
- advisory and operator communications; and
- corrective actions with owners and due dates.

Run a retrospective and update the threat model, runbooks, release workflow,
and tests. A tabletop exercise must be completed before this procedure can be
counted as production-readiness evidence.
