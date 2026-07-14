# Release qualification checklist

Copy this checklist into the evidence record for the exact release commit.
Unchecked items are failures unless the checklist explicitly permits `N/A` and
records why. Do not edit an old checklist to represent a different artifact.

## Identity and approvals

- [ ] Version and annotated tag follow the documented semantic-version format.
- [ ] Tag commit is reachable from the reviewed release line.
- [ ] Changelog and release notes identify breaking, migration, security,
      deprecation, rollback, and unsupported-capability changes.
- [ ] Product approval: reviewer, commit, date, and disposition recorded.
- [ ] Security approval: reviewer, commit, date, and disposition recorded.
- [ ] Operations/QA approval: reviewer, commit, date, and disposition recorded.
- [ ] Release approval is provided by someone other than the artifact builder.

## Compatibility and data

- [ ] Every affected compatibility surface is classified under
      [compatibility.md](./compatibility.md).
- [ ] Supported source versions migrate successfully on every claimed database.
- [ ] Failed-migration, restart, backup, restore, and data-preservation results
      are attached.
- [ ] Rollback or forward-fix boundaries are explicit.
- [ ] Configuration and secret changes include operator migration instructions.
- [ ] Token, session, webhook, audit-event, SDK, and package compatibility is
      reviewed where affected.

## Qualification

- [ ] Required Rust format, Clippy, test, migration, and database-runtime checks pass.
- [ ] Required JavaScript lint, type, test, build, and clean-install checks pass.
- [ ] Dependency, secret, static-analysis, and license checks pass under the
      documented severity policy.
- [ ] Protocol, tenant-isolation, abuse-case, restore, upgrade, and smoke suites
      required for this release pass.
- [ ] No unresolved critical/high security finding exists; every accepted lower
      finding records owner, mitigation, and due date.
- [ ] Flaky failures and retries are visible and dispositioned.

## Artifacts and supply chain

- [ ] All standalone, OCI, and npm artifacts were prepared in read-only jobs;
      the coordinated absence preflight passed before the first registry write.
- [ ] Privileged jobs downloaded and checksum-verified prepared artifacts and
      did not checkout or execute repository source.
- [ ] Standalone archives, checksums, installer, and embedded versions match the tag.
- [ ] Every standalone artifact has a digest, SBOM, provenance/attestation, and
      verification instructions.
- [ ] Every Docker variant has an immutable digest, SBOM, provenance, expected
      platform set, and non-root/runtime-hardening result.
- [ ] Every npm package has the tag version, expected dependency graph,
      provenance, SBOM, and tarball-content review.
- [ ] A release manifest links all artifacts, digests, SBOMs, attestations, test
      reports, migration evidence, and approvals.
- [ ] An isolated rebuild comparison is attached or non-reproducible fields are explained.

## Post-publication verification

- [ ] A clean environment verifies every published artifact and records the transcript.
- [ ] Installer selection and checksum verification succeed for each supported platform.
- [ ] Published images boot with each database variant and pass health/readiness smoke tests.
- [ ] npm and SDK consumer smoke projects install the published versions and build.
- [ ] Release, registry, image, and package metadata identify the same commit/version.
- [ ] Support status, affected versions, and end-of-life information are accurate.
- [ ] Failed or superseded artifacts are withdrawn without replacing bytes in place.
- [ ] If publication was partial, the exact public subset is recorded, the
      failed version is not rerun or completed, and recovery uses a new reviewed
      commit plus a strictly new annotated version.

## Evidence record

Record the release tag, commit SHA, workflow run URLs, artifact manifest digest,
reviewers, completion time, exceptions, and follow-up owners. The checklist is
complete only after post-publication verification; successful upload alone is
not a completed release.
