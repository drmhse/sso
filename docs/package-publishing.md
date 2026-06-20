# Package Publishing

AuthOS publishes public npm packages from `.github/workflows/publish-npm-packages.yml`.

The workflow runs on tags matching `v*`. The pushed tag is the source of truth
for every public package version: pushing `v1.0.0` publishes each package as
`1.0.0`.

The workflow installs dependencies, stamps package versions from the tag,
typechecks the SDK and framework packages, builds them, then publishes only
package versions that do not already exist on npm.

Published workspaces, in dependency order:

- `@drmhse/sso-sdk`
- `@drmhse/authos-node`
- `@drmhse/authos-react`
- `@drmhse/authos-vue`
- `@drmhse/authos-cli`

`lite-web-client` is private and is not published.

## Required GitHub Configuration

Add this repository secret:

- `NPM_TOKEN`: npm automation token with publish access to the `@drmhse` scope.

The workflow uses these GitHub permissions:

- `contents: read`
- `id-token: write`

`id-token: write` enables npm provenance on real tag-triggered publishes.

## Required npm Configuration

In npm:

1. Ensure the `@drmhse` organization or scope exists.
2. Ensure the token owner has publish access for:
   - `@drmhse/sso-sdk`
   - `@drmhse/authos-node`
   - `@drmhse/authos-react`
   - `@drmhse/authos-vue`
   - `@drmhse/authos-cli`
3. Create an automation token and store it as GitHub secret `NPM_TOKEN`.

## Release Flow

1. Commit the code/docs changes you want to release.
2. Push a tag matching `vX.Y.Z`, for example:

   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```

The tag version is applied to all public package manifests in the workflow
runner before build and publish. Internal package dependencies on
`@drmhse/sso-sdk` are also stamped to the same exact version.

The workflow skips any `name@version` already published to npm, so retrying a
tag is safe for packages that were already published successfully.

For a validation run without publishing, use the manual workflow dispatch, set
the version to test, and leave `dry_run` enabled.
