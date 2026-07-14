# Verify AuthOS release artifacts

Releases produced by the current release workflow publish SHA-256 checksums,
SPDX 2.3 SBOMs, and keyless GitHub artifact attestations for standalone
bundles. Their Docker images include registry-attached BuildKit provenance and
SBOM attestations, and their image digests receive a GitHub provenance
attestation.

These controls apply only after a release has successfully completed the
hardened workflow. Older releases, including `v0.8.2`, predate these controls;
inspect a release's assets and attestations before assuming they are present.

Replace `vX.Y.Z` and `ARCH` in the examples with the release and architecture
you downloaded.

## Check downloaded release assets

Download `install.sh`, both standalone archives, both `.spdx.json` files,
`authos-standalone-release-manifest.json`, and `SHA256SUMS.txt` into the same
directory, then run:

```bash
python3 scripts/verify-release-assets.py /path/to/downloaded-assets
```

The verifier requires the exact release inventory, validates every SHA-256,
checks the manifest's tag, full source commit, workflow run, payload digests,
and archive-to-SBOM mapping, validates both SPDX documents, and rejects unsafe
archive paths, links, devices, and FIFOs without extracting the bundles. The
manifest scope is deliberately `standalone-linux`; Docker digests and npm
package evidence remain registry/workflow evidence and must be recorded by the
release checklist. If you do not have the source tree,
`sha256sum --check SHA256SUMS.txt` remains the minimum checksum-only check.

The checksum file detects corruption but is not a signature. Verify the
keyless attestation as well:

```bash
gh attestation verify authos-sqlite-linux-ARCH.tar.gz \
  --repo drmhse/AuthOS \
  --signer-workflow drmhse/AuthOS/.github/workflows/release.yml \
  --source-ref refs/tags/vX.Y.Z
```

Verify that the published SPDX document is the SBOM attested for that archive:

```bash
gh attestation verify authos-sqlite-linux-ARCH.tar.gz \
  --repo drmhse/AuthOS \
  --signer-workflow drmhse/AuthOS/.github/workflows/release.yml \
  --source-ref refs/tags/vX.Y.Z \
  --predicate-type https://spdx.dev/Document/v2.3
```

## Verify a Docker image

Authenticate to Docker Hub if needed, then verify the image against the GitHub
attestation service:

```bash
docker login docker.io
gh attestation verify oci://docker.io/editoredit/sso:sqlite-vX.Y.Z \
  --repo drmhse/AuthOS \
  --signer-workflow drmhse/AuthOS/.github/workflows/release.yml \
  --source-ref refs/tags/vX.Y.Z
```

Docker's BuildKit SBOM and provenance are attached to the multi-platform image
index in Docker Hub. Use an immutable digest instead of a mutable `latest` tag
when recording or deploying a verified image. Each backend also publishes an
attested `authos-docker-BACKEND-manifest.json` release asset that binds the
immutable multi-platform digest to the release tag, commit, workflow run, and
expected registry evidence. Verify the record locally, then compare its digest
to the registry index:

```bash
python3 scripts/container-release-evidence.py verify \
  authos-docker-sqlite-manifest.json
docker buildx imagetools inspect \
  docker.io/editoredit/sso:sqlite-vX.Y.Z
```

## Verify npm packages

The npm publication workflow packs each workspace once, generates an SPDX 2.3
SBOM for that exact tarball, calculates SHA-256 checksums, and publishes the
same tarball to npm. Tag-triggered runs also create GitHub build-provenance and
SBOM attestations; npm publication uses npm provenance. The exact tarballs,
SBOMs, `npm-SHA256SUMS.txt`, and `authos-npm-release-manifest.json` are attached
to the GitHub release instead of existing only in a retention-bound workflow
artifact.

Download those npm evidence assets from the release (or the matching
`npm-package-evidence` workflow artifact), then verify the exact inventory,
package names/versions, SPDX documents, source identity, mappings, and digests:

```bash
cd npm-package-evidence
python3 scripts/npm-release-evidence.py verify .
sha256sum --check npm-SHA256SUMS.txt
gh attestation verify authos-node.tgz \
  --repo drmhse/AuthOS \
  --signer-workflow drmhse/AuthOS/.github/workflows/publish-npm-packages.yml \
  --source-ref refs/tags/vX.Y.Z
gh attestation verify authos-node.tgz \
  --repo drmhse/AuthOS \
  --signer-workflow drmhse/AuthOS/.github/workflows/publish-npm-packages.yml \
  --source-ref refs/tags/vX.Y.Z \
  --predicate-type https://spdx.dev/Document/v2.3
```

Repeat the attestation checks for `sso-sdk.tgz`, `authos-react.tgz`,
`authos-vue.tgz`, and `authos-cli.tgz`. After installing a release in a clean
test project, `npm audit signatures` verifies registry signatures and available
npm provenance attestations. A workflow artifact is retention-bound; release
qualification must use the release-attached manifest and SBOMs as the durable
record, while treating the workflow artifact as a convenience copy.
