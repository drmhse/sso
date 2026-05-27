# AuthOS

Open-source authentication infrastructure for B2B and B2B2C products.

This public repository contains the Rust API, the TypeScript SDKs and adapters, and the lightweight embedded web client used by the standalone Linux bundles. The larger internal multi-tenant operations dashboard is not part of this repo.

## Repository Structure

| Path | Description |
|------|-------------|
| [api/](./api) | Rust API and standalone binaries (`sso_sqlite`, `sso_psql`, `sso_mysql`). |
| [lite-web-client/](./lite-web-client) | Embedded setup and end-user journey UI served directly by the API binary. |
| [sso-sdk/](./sso-sdk) | Framework-agnostic TypeScript SDK. |
| [packages/authos-react/](./packages/authos-react) | React and Next.js adapter package. |
| [packages/authos-vue/](./packages/authos-vue) | Vue 3 and Nuxt adapter package. |
| [packages/authos-node/](./packages/authos-node) | Node.js server adapter package. |
| [packages/authos-cli/](./packages/authos-cli) | Scaffolding CLI package. |
| [scripts/authos-standalone/](./scripts/authos-standalone) | Standalone Linux installer sources bundled into release artifacts. |
| [scripts/authos-bootstrap/](./scripts/authos-bootstrap) | Release bundle builder for compressed standalone artifacts. |

## What the Lite Client Covers

The embedded lite client is the public-facing bootstrap surface for the standalone build. It is intentionally narrower than the internal admin dashboard.

It covers:
- hosted sign-in and sign-up journeys
- email verification and password reset flows
- invitation acceptance
- a single-platform setup workspace
- platform owner account and organization basics
- lightweight application and end-user management
- managed config editing through structured form fields

It does not expose the full internal multi-tenant operations surface.

## Standalone Linux Bundles

AuthOS can run without Docker and without Node.js on the target server.

The standalone SQLite bundle contains:
- the `authos` binary
- the embedded lite web client
- `install.sh`
- the standalone installer helper
- `authos.config.example.json`

The intended public release targets are:
- `linux/amd64`
- `linux/arm64`

## Docker Images

Tagged releases also publish Docker images for all three database backends on Docker Hub:

- SQLite default: `editoredit/sso:latest`, `editoredit/sso:vX.Y.Z`, `editoredit/sso:X.Y.Z`
- Explicit SQLite: `editoredit/sso:sqlite-latest`, `editoredit/sso:sqlite-vX.Y.Z`, `editoredit/sso:sqlite-X.Y.Z`
- PostgreSQL: `editoredit/sso:psql-latest`, `editoredit/sso:psql-vX.Y.Z`, `editoredit/sso:psql-X.Y.Z`
- MySQL: `editoredit/sso:mysql-latest`, `editoredit/sso:mysql-vX.Y.Z`, `editoredit/sso:mysql-X.Y.Z`

Every `v*` release tag publishes the exact git tag alias and a compatibility alias without the leading `v`.

### Install From GitHub Releases

On a Linux host with `systemd` and `python3`:

```bash
curl -fsSL -o install.sh https://github.com/drmhse/AuthOS/releases/latest/download/install.sh
chmod +x install.sh
sudo ./install.sh
```

The release installer detects `amd64` vs `arm64`, downloads the matching standalone bundle,
extracts it, and runs the bundled installer.

If you want a specific release instead of the latest one:

```bash
AUTHOS_VERSION=v0.1.41
curl -fsSL -o install.sh "https://github.com/drmhse/AuthOS/releases/download/${AUTHOS_VERSION}/install.sh"
chmod +x install.sh
sudo AUTHOS_RELEASE_TAG="${AUTHOS_VERSION}" ./install.sh
```

Two supported bootstrap modes:

1. Zero-config install: run `sudo ./install.sh` with no config file. AuthOS starts, prints a one-time bootstrap link, and the lite client opens the setup workspace at `/app#setup`.
2. File-driven install: copy `authos.config.example.json` to `authos.config.json`, edit it, then run `sudo ./install.sh --config ./authos.config.json`.

The setup workspace writes back to the managed `config.json` on disk and can queue a reload of the running service after changes are saved.

### Optional Caddy

The standalone installer supports an optional Caddy front-end for domain-based deployments. Host-level install controls stay outside the web-editable config surface; once the local admin enables Caddy, the managed setup form can update the domain-facing configuration and trigger a safe reload.

## Local Build and Packaging

Prerequisites for building standalone bundles locally:
- Node.js 18+
- Rust stable
- `cargo-zigbuild`
- `zig`
- `upx`
- `binutils` (`objdump`)

Install workspace dependencies:

```bash
npm install
```

Build a compressed standalone bundle:

```bash
npm run authos:binary -- --backend sqlite --platform linux/amd64
npm run authos:binary -- --backend sqlite --platform linux/arm64
```

Artifacts are written to `.authos/releases/`.

The build path does three relevant things before emitting the archive:
- Vite tree-shakes the lite client production assets
- Rust builds with the size-focused release profile in [api/Cargo.toml](./api/Cargo.toml)
- `upx --best --lzma` compresses the shipped binary and verifies the packed executable

The bundle builder also prints section and size information so the binary footprint can be checked before release automation is changed.

## GitHub Actions Release Flow

The standalone release workflow lives in [.github/workflows/release-standalone.yml](./.github/workflows/release-standalone.yml).
The Docker image release workflow lives in [.github/workflows/release-docker.yml](./.github/workflows/release-docker.yml).

It:
- builds `linux/amd64` and `linux/arm64` standalone SQLite bundles
- runs the same local release builder used in development
- uploads release artifacts for manual runs
- attaches the bundles and checksums to tagged GitHub releases

The Docker workflow:
- stages exact-tag binaries for `linux/amd64` and `linux/arm64`
- builds multi-arch Docker images for SQLite, PostgreSQL, and MySQL
- publishes `latest`, backend-specific `*-latest`, exact git-tag aliases, and compatibility aliases without the leading `v`

Tag pushes matching `v*` publish both standalone release assets and Docker images. `workflow_dispatch` on the standalone workflow still builds artifacts without requiring a tag.

## Running the API Directly

If you want the raw API without the standalone installer:

```bash
cd api
cp .env.example .env
cargo run --release
```

Keep `PLATFORM_BASE_URL` pointed at the embedded lite client unless you are
explicitly handing off to a separate full web client. With the default example
env, that means leaving it on `http://localhost:3001`.

For direct Cargo work, the API will still compile if `lite-web-client/dist` has not been built yet. In that case it embeds a placeholder page instead of failing the build.

## SDK Usage

Install only the package you need:

```bash
npm install @drmhse/authos-react
npm install @drmhse/authos-vue
npm install @drmhse/authos-node
```

Nuxt and Vue users can configure either `baseURL` or `baseUrl`; both are supported by the public adapter runtime.

## Development Checks

Typical verification commands:

```bash
npm run build
npm run typecheck
cd api && cargo check
```

To validate the standalone packaging path specifically:

```bash
npm --workspace lite-web-client run build
cargo check --manifest-path api/Cargo.toml --no-default-features --features db_sqlite --bin sso_sqlite
npm run authos:binary -- --backend sqlite --platform linux/amd64
npm run authos:docker:dist -- --backend sqlite
```

## License

AuthOS is split across two first-party license buckets:

- API: [AGPL-3.0-only](./LICENSES/AGPL-3.0.txt)
- SDKs and packages: [MIT](./LICENSES/MIT.txt)

Vendored third-party code keeps its upstream notices in place under its own directory.
See [LICENSE](./LICENSE) for the repository licensing map.
