# AuthOS

Open-source authentication infrastructure for B2B and B2B2C products.

AuthOS ships a Rust API, standalone Linux bundles, Docker images, TypeScript
SDKs, framework adapters, and an embedded lightweight web client for setup and
end-user journeys.

## Install

On a Linux host with `systemd`, `python3`, `curl`, and `tar`:

```bash
curl -fsSL -o install.sh https://github.com/drmhse/AuthOS/releases/latest/download/install.sh
chmod +x install.sh
sudo ./install.sh
```

The installer downloads the matching SQLite standalone bundle for `linux/amd64`
or `linux/arm64`, starts AuthOS, and prints a one-time bootstrap link.

To install a specific release:

```bash
AUTHOS_VERSION=v0.8.2
curl -fsSL -o install.sh "https://github.com/drmhse/AuthOS/releases/download/${AUTHOS_VERSION}/install.sh"
chmod +x install.sh
sudo AUTHOS_RELEASE_TAG="${AUTHOS_VERSION}" ./install.sh
```

## Docker

Tagged releases publish multi-arch images for all database backends:

- SQLite default: `editoredit/sso:latest`, `editoredit/sso:vX.Y.Z`, `editoredit/sso:X.Y.Z`
- Explicit SQLite: `editoredit/sso:sqlite-latest`, `editoredit/sso:sqlite-vX.Y.Z`, `editoredit/sso:sqlite-X.Y.Z`
- PostgreSQL: `editoredit/sso:psql-latest`, `editoredit/sso:psql-vX.Y.Z`, `editoredit/sso:psql-X.Y.Z`
- MySQL: `editoredit/sso:mysql-latest`, `editoredit/sso:mysql-vX.Y.Z`, `editoredit/sso:mysql-X.Y.Z`

## Packages

Install only the package your app needs:

```bash
npm install @drmhse/sso-sdk
npm install @drmhse/authos-react
npm install @drmhse/authos-vue
npm install @drmhse/authos-node
npm install @drmhse/authos-cli
```

Public packages are released from the same `vX.Y.Z` tag as the standalone
bundles and Docker images. Pushing `v1.0.0` publishes each public package as
`1.0.0`.

## Repository

| Path | Description |
|------|-------------|
| [api/](./api) | Rust API and backend binaries. |
| [lite-web-client/](./lite-web-client) | Embedded setup and end-user journey UI. |
| [sso-sdk/](./sso-sdk) | Framework-agnostic TypeScript SDK. |
| [packages/](./packages) | React, Vue, Node, and CLI packages. |
| [scripts/](./scripts) | Installer and release bundle tooling. |

## Docs

- [Enterprise-managed authorization](./docs/enterprise-managed-authorization.md)
- [SCIM provisioning setup](./docs/scim-provisioning.md)
- [Organization roles and permissions](./docs/organization-roles.md)
- [Package publishing](./docs/package-publishing.md)

AuthOS also maintains source-verified Agent Skills for integration and
operations workflows:

- [github.com/drmhse/authos_skill](https://github.com/drmhse/authos_skill)
- [skills.sh/drmhse/authos_skill](https://skills.sh/drmhse/authos_skill)

## Development

Install workspace dependencies:

```bash
npm install
```

Common checks:

```bash
npm run typecheck
npm run build
cargo check --manifest-path api/Cargo.toml
```

For direct API work:

```bash
cd api
cp .env.example .env
cargo run --release
```

## Release

AuthOS releases are tag-driven. A pushed `vX.Y.Z` tag builds standalone assets,
publishes Docker images, generates GitHub release notes, and publishes public
npm packages with version `X.Y.Z`.

Release workflow details live in:

- [.github/workflows/release.yml](./.github/workflows/release.yml)
- [.github/workflows/publish-npm-packages.yml](./.github/workflows/publish-npm-packages.yml)
- [docs/package-publishing.md](./docs/package-publishing.md)

## License

AuthOS is split across two first-party license buckets:

- API: [AGPL-3.0-only](./LICENSES/AGPL-3.0.txt)
- SDKs and packages: [MIT](./LICENSES/MIT.txt)

Vendored third-party code keeps its upstream notices in place under its own
directory. See [LICENSE](./LICENSE) for the repository licensing map.
