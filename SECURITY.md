# Security Policy

AuthOS handles authentication, authorization, and identity data. We welcome
responsible reports that help protect AuthOS operators and their users.

## Supported versions

AuthOS is currently pre-1.0 and evolves quickly. Security fixes are made on the
current development line and included in the next release. Only the latest
published release is supported; earlier releases are unsupported and do not
receive routine backports.

| Version | Security support |
|---------|------------------|
| Latest published release | Supported |
| Earlier releases | Unsupported |
| Unreleased development snapshots | Not supported for deployment |

Operators should follow the
[GitHub releases](https://github.com/drmhse/AuthOS/releases) page and upgrade to
the latest release after testing it in their environment. AuthOS does not yet
publish a fixed release cadence or long-term-support schedule.

## Reporting a vulnerability

Do not open a public GitHub issue for a suspected vulnerability. Email
[info@authos.dev](mailto:info@authos.dev) with the subject
`AuthOS security report`.

Include enough information for us to reproduce and assess the issue:

- the affected component and version or commit;
- the deployment and database type, where relevant;
- a clear description of the impact and the security boundary crossed;
- minimal reproduction steps or a proof of concept;
- any mitigations you have identified; and
- how you would like to be credited, or whether you prefer to remain anonymous.

Do not include live credentials, access tokens, private keys, personal data, or
data from systems you do not own. If sensitive supporting material is needed,
ask for a suitable transfer method in the initial email.

We aim to acknowledge a report within five business days and provide an initial
assessment within ten business days. These are best-effort targets, not an SLA
or a remediation deadline. We triage reports based on reproducibility, impact,
affected deployments, and the availability of a safe fix. We may ask for
additional information and will try to keep the reporter informed as the report
progresses.

Please allow time for investigation and a release before publishing details.
We will coordinate disclosure timing with the reporter where practical. A
report may be closed when it cannot be reproduced, is not a security boundary
violation, affects only an unsupported version, or concerns a third-party
system outside AuthOS's control.

When a report affects AuthOS, maintainers will use a private GitHub security
advisory when practical, coordinate a fix and release, and publish an advisory
that identifies affected and fixed versions. A CVE may be requested when the
issue meets the applicable assignment criteria. Exploit details may be delayed
until users have had a reasonable opportunity to update.

## Scope

This policy covers first-party code in this repository, the AuthOS packages
published from it, and AuthOS release artifacts produced from it.

Examples of useful reports include:

- authentication or authorization bypasses;
- cross-tenant data access or privilege escalation;
- token, session, key, or credential disclosure;
- unsafe OAuth, OpenID Connect, SAML, SCIM, passkey, MFA, or recovery behavior;
- injection, request forgery, path traversal, or remote code execution; and
- vulnerabilities in the installer, update path, or release packaging.

The following are generally outside this project's security scope:

- account recovery or configuration support for a third-party AuthOS instance;
- vulnerabilities in an operator's infrastructure or custom integrations that
  are not caused by AuthOS;
- findings that require already-authorized administrator access and do not
  cross another documented security boundary;
- automated scanner output without a reproducible impact; and
- denial-of-service tests against systems you do not own or have permission to
  test.

Contact the operator of a deployed AuthOS instance for account or incident
support. Report vulnerabilities in third-party dependencies to their
maintainers as well as to AuthOS when the dependency creates an exploitable
condition in AuthOS.

## Safe research

Test only systems and data you own or are explicitly authorized to assess.
Avoid privacy violations, service disruption, social engineering, and actions
that alter or destroy data. This policy is not a bug-bounty program and does
not promise payment or legal safe harbor.
