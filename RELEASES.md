# AuthOS releases and versioning

AuthOS uses one public release identity for coordinated artifacts: an annotated
Git tag in the form `vMAJOR.MINOR.PATCH`. The latest published release at this
document's baseline is `v0.8.2`.

## Version sources

The release tag is authoritative for shipped artifacts:

- standalone binaries embed the tag through `AUTHOS_BUILD_VERSION`;
- Docker images receive `backend-vX.Y.Z`, `backend-X.Y.Z`, and
  `backend-latest` tags;
- the npm publication workflow stamps every public `@drmhse/*` package from
  the release tag and aligns internal SDK dependency versions; and
- `install.sh` uses the latest GitHub release unless an operator supplies
  `AUTHOS_RELEASE_TAG`.

Some checked-in manifests are development metadata rather than public release
identities. The private workspace root remains `0.0.0`, the private embedded
web client has its own source version, and the Rust crate version is the local
fallback when a build has neither an exact Git tag nor
`AUTHOS_BUILD_VERSION`. Public packages keep a common checked-in development
version and are stamped during publication.

`npm run check:trust` verifies the relationships that must remain consistent:
the public package source versions, their internal SDK dependencies, the
documented current release, and bootstrap Docker pins.

## Current release lifecycle

1. Changes are reviewed through a pull request and the baseline CI workflow.
2. The maintainer verifies the release commit, changelog, migrations, and
   public support labels before creating a release tag.
3. A `vX.Y.Z` tag starts the standalone/Docker release workflow and the npm
   publication workflow for the same source commit.
4. The maintainer verifies the GitHub release assets and checksums, Docker
   variant tags, npm package versions/provenance, and embedded build version.
5. Failures are corrected with a new commit and tag; published artifacts are
   not silently replaced with different bytes under the same version.

Both publishing workflows qualify the exact tagged commit before they build or
publish. They require an annotated, v-prefixed semantic-version tag whose
commit is reachable from `main`. The standalone and Docker workflow runs the
full Rust and frontend baseline; the npm workflow independently reruns the same
Rust checks plus trust validation, linting, typechecking, tests, and builds for
the JavaScript workspaces. A manual npm dispatch follows the same qualification
but is unconditionally dry-run-only; only a qualified annotated tag can publish.

## Pre-1.0 compatibility

Pre-1.0 releases may change APIs, configuration, SDK behavior, or migrations.
Breaking and migration-relevant changes belong in [CHANGELOG.md](./CHANGELOG.md)
and the GitHub release notes. Operators should pin an exact version, back up
state, and exercise upgrades in a representative environment.

Only the latest published release receives routine security support. See
[SECURITY.md](./SECURITY.md) and [PROJECT_STATUS.md](./PROJECT_STATUS.md) for
the current support boundary.
