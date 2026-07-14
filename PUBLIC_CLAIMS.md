# AuthOS public claim audit

Baseline date: 2026-07-13  
Status: in progress until every external setting and deployed page is verified

AuthOS treats public maturity, performance, compatibility, security, and
availability statements as claims that require evidence. This checklist keeps
the desired wording and remaining external work reviewable in the repository.

| Surface | Claim or signal | Disposition | Evidence or required action |
| --- | --- | --- | --- |
| GitHub description | Ends in `Beta` and describes AuthOS primarily as social SSO. | **Replace.** | Use: `Self-hosted identity infrastructure for multi-tenant B2B products, with a Rust API, enterprise federation, provisioning, and TypeScript SDKs.` |
| GitHub topics | Discovery metadata is incomplete. | **Add.** | Proposed topics: `authentication`, `authorization`, `b2b`, `identity`, `multi-tenant`, `oauth2`, `oidc`, `passkeys`, `rust`, `saml`, `scim`, `self-hosted`, `sso`. |
| Repository README | Feature-rich project could be read as generally production-ready. | **Qualified in this change set.** | README links to [PROJECT_STATUS.md](./PROJECT_STATUS.md) and [PRODUCTION_READINESS.md](./PRODUCTION_READINESS.md). |
| Website performance section | `12ms` P50, `~18MB` idle RAM, and `25M` MAUs on one SQLite node are presented as benchmark facts. | **Remove until evidenced.** | Reintroduce numbers only with a public harness, commit, environment, workload, raw results, and limitations. |
| Website observability preview | Animated RPS, latency, session, and threat totals can look like live product results. | **Label as simulated UI.** | The deployed preview must visibly say that its data is illustrative and not benchmark or production telemetry. |
| Protocol claims | OAuth/OIDC, SAML, SCIM, passkeys, and MFA are advertised without public conformance/interoperability reports. | **Qualify per profile.** | Keep implemented capabilities Beta, but keep upstream SAML unsupported because response verification is unimplemented. Do not use `compliant`, `certified`, or stable language until the Phase 2 evidence is published. |
| Database claims | SQLite, PostgreSQL, and MySQL are advertised without a runtime/version matrix. | **Qualify.** | [PROJECT_STATUS.md](./PROJECT_STATUS.md) states the missing support window and the SQLite single-node boundary. |
| Installer integrity | `v0.8.2` publishes checksums, but its released installer predates automatic verification and the hardened release workflow. | **Implemented for a future release; not yet published.** | Current source verifies the selected archive and the workflow generates SBOMs and attestations. Mark this verified only after a new release completes that workflow and its assets are independently checked. |
| HA and production readiness | No general HA or stable-root-identity guarantee is evidenced. | **Do not advertise.** | Keep multi-node/HA unsupported until Phase 3 exercises pass. |
| Licensing | The existing path map does not assign every first-party root, tooling, or embedded-client path. | **Disclose and resolve.** | README, [CONTRIBUTING.md](./CONTRIBUTING.md), and [LICENSE](./LICENSE) identify the unassigned paths. A maintainer must choose licenses before the repository claims complete open-source coverage. |

## External verification checklist

- [ ] Update the GitHub description and topics to the reviewed values above.
- [ ] Require the baseline CI checks on the protected default branch.
- [ ] Enable and verify the intended GitHub security settings and private
      vulnerability-reporting path.
- [ ] Publish the website claim corrections and verify the live pages.
- [ ] Assign licenses to the currently unassigned first-party paths and update
      their package/file notices.
- [ ] Record Product plus Security or Release reviewer approval here with the
      commit and date.

The unchecked items require repository-administration or website-deployment
access. Their presence here must not be interpreted as completion.
