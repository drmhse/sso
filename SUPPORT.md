# AuthOS Support

AuthOS is an open-source, self-hosted project. Public support is currently
provided on a best-effort basis; there is no guaranteed response time, service
level agreement, or published long-term-support schedule.

## Where to get help

- Read the [AuthOS documentation](https://authos.dev/docs/) and the repository
  [README](./README.md) first.
- Search [existing GitHub issues](https://github.com/drmhse/AuthOS/issues) for
  known behavior and workarounds.
- Open a [new GitHub issue](https://github.com/drmhse/AuthOS/issues/new) for a
  reproducible defect or documentation problem.
- Email [info@authos.dev](mailto:info@authos.dev) for a private, non-security
  project inquiry.
- Follow [GitHub releases](https://github.com/drmhse/AuthOS/releases) for
  release notes and new versions.

Suspected vulnerabilities must follow [SECURITY.md](./SECURITY.md) and must not
be posted in a public issue.

The maintainers do not currently advertise a separate paid support plan. Do not
send credentials, private keys, access tokens, personal data, or production
database contents through an issue or unsolicited email.

## Before opening an issue

Use the latest published AuthOS release when possible. AuthOS is pre-1.0, and
older releases are unsupported. Confirm that the problem is in
AuthOS rather than a reverse proxy, identity provider, database, browser
extension, or application integration.

For a useful report, include:

- the AuthOS version or commit and installation method;
- operating system, architecture, and database backend;
- the relevant SDK or package name and version, if applicable;
- expected and actual behavior;
- the smallest set of steps that reproduces the issue;
- sanitized logs, error messages, or configuration excerpts; and
- whether the problem still occurs on the latest release.

Please reduce logs to the relevant portion and redact secrets and user data.
For deployment problems, explain the network path (for example, reverse proxy
to AuthOS) without publishing private infrastructure details.

## Support boundaries

The operator of each AuthOS deployment is responsible for its infrastructure,
TLS termination, access controls, secret storage, backups, monitoring, database
availability, disaster recovery, and upgrade validation. The AuthOS community
can help investigate product behavior but cannot operate or recover a deployment
it does not control.

End users should contact the organization that operates the AuthOS instance for
password resets, MFA recovery, account access, invitations, or data requests.
The upstream project cannot verify an end user's identity or administer a
third-party instance.

Pre-1.0 releases may change configuration, APIs, migrations, and SDK behavior.
Review release notes, back up the deployment, and test upgrades outside
production before rollout.
