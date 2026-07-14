# Contributing to AuthOS

Thank you for helping improve AuthOS. Contributions can include focused bug
fixes, tests, documentation, SDK improvements, and security hardening.

## Start with an issue

Search [existing issues](https://github.com/drmhse/AuthOS/issues) before doing
substantial work. Open an issue describing the problem and proposed direction
for large features, protocol changes, schema changes, or changes to a public
API. This gives maintainers and other contributors a chance to align on scope
before implementation.

For suspected vulnerabilities, stop and follow [SECURITY.md](./SECURITY.md)
instead of opening a public issue.

## Repository layout

| Path | Purpose |
|------|---------|
| `api/` | Rust API, database migrations, and backend binaries |
| `lite-web-client/` | Vue and Vite web client embedded in release bundles |
| `sso-sdk/` | Framework-independent TypeScript SDK |
| `packages/` | React, Vue, Node, and CLI packages |
| `scripts/` | Installer, bootstrap, and release tooling |

## Development setup

The JavaScript workspace requires Node.js 20.19 or newer, 22.13 or newer, or
24 or newer. Install a current stable Rust toolchain for API work. From the
repository root:

```bash
npm ci
npm run build:sdk
npm run check:trust
npm run lint
npm run typecheck
npm run build
cargo check --manifest-path api/Cargo.toml
```

To run the API directly, create a local configuration from the checked-in
example. Never commit the resulting `.env` file or real credentials.

```bash
cd api
cp .env.example .env
cargo run
```

The example documents the required keys and supported database feature flags.
Supporting development services are also defined in
`api/docker-compose.dev.yml`.

## Checks

Run the checks relevant to every component you change. The baseline repository
checks are:

```bash
npm run lint
npm run typecheck
npm run test --workspaces --if-present
npm run build
npm run check:trust
cargo fmt --manifest-path api/Cargo.toml --all -- --check
cargo clippy --manifest-path api/Cargo.toml --locked --package sso --all-targets --no-deps -- -D warnings
cargo test --manifest-path api/Cargo.toml --locked --package sso --all-targets
```

The CI baseline rejects both Rust and JavaScript lint warnings. State which
commands you ran, their results, and why any relevant check was not run in the
pull request.

When changing database behavior, use a new migration under
`api/migration/src/`; do not edit an operator's database by hand. Exercise the
change against each affected database backend: SQLite, PostgreSQL, and MySQL.
When changing an authentication or tenant boundary, include tests for both the
allowed path and unauthorized or cross-tenant paths.

## Pull requests

Keep a pull request focused enough to review and revert independently. Include:

- the problem and the chosen solution;
- any security, compatibility, migration, or operational impact;
- tests added or updated and the commands run;
- documentation changes for user-visible behavior; and
- screenshots for visible web-client changes.

Avoid unrelated formatting or generated-file churn. Do not commit secrets,
private data, build output, dependency caches, or local environment files.

Review feedback may request changes before a contribution is merged. A
submission is not guaranteed to be accepted, and maintainers may close work
that conflicts with the project's direction or security model.

## Licensing

AuthOS uses path-specific licenses. The API, lite web client, scripts, and
installer are AGPL-3.0-only; the SDK and published packages are MIT licensed.
[LICENSE](./LICENSE) is the authoritative map and identifies the remaining root
documentation and configuration whose license is not yet assigned. Confirm the
intended license with a maintainer before contributing to an unmapped path. By
submitting a contribution to a licensed path, you agree
that it may be distributed under that path's license and that you have the
right to submit the work under that license.
