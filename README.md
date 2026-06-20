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

## Packages

Install only the package your app needs:

```bash
npm install @drmhse/sso-sdk
npm install @drmhse/authos-react
npm install @drmhse/authos-vue
npm install @drmhse/authos-node
npm install @drmhse/authos-cli
```

## Repository

| Path | Description |
|------|-------------|
| [api/](./api) | Rust API and backend binaries. |
| [lite-web-client/](./lite-web-client) | Embedded setup and end-user journey UI. |
| [sso-sdk/](./sso-sdk) | Framework-agnostic TypeScript SDK. |
| [packages/](./packages) | React, Vue, Node, and CLI packages. |
| [scripts/](./scripts) | Installer and release bundle tooling. |

## Docs

- [Getting started](https://authos.dev/docs/api/getting-started/)
- [Authentication API](https://authos.dev/docs/api/reference/authentication/)
- [SDK packages](https://authos.dev/docs/packages/)
- [Enterprise-managed authorization](https://authos.dev/docs/api/reference/authentication/enterprise-managed-authorization/)
- [SCIM provisioning](https://authos.dev/docs/sdk/guides/scim-provisioning/)

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

## License

AuthOS is split across two first-party license buckets:

- API: [AGPL-3.0-only](./LICENSES/AGPL-3.0.txt)
- SDKs and packages: [MIT](./LICENSES/MIT.txt)

Vendored third-party code keeps its upstream notices in place under its own
directory. See [LICENSE](./LICENSE) for the repository licensing map.
