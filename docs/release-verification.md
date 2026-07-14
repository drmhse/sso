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

Download `install.sh`, both standalone archives, both `.spdx.json` files, and
`SHA256SUMS.txt` into the same directory, then run:

```bash
sha256sum --check SHA256SUMS.txt
```

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
when recording or deploying a verified image.
