#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-only

import { readFile } from 'node:fs/promises';

const root = new URL('../', import.meta.url);
const release = await readFile(new URL('.github/workflows/release.yml', root), 'utf8');
const npmPublish = await readFile(new URL('.github/workflows/publish-npm-packages.yml', root), 'utf8');

function requireText(document, expected, label) {
  if (!document.includes(expected)) {
    throw new Error(`${label}: missing ${JSON.stringify(expected)}`);
  }
}

requireText(release, 'group: authos-public-release', 'cross-version release serialization');
requireText(
  release,
  `mode: prepare
    permissions:
      # This is the permission ceiling for every job in the reusable workflow.
      # Its prepare/qualification jobs still narrow themselves to contents:read;
      # only the separately invoked publish mode can use these write scopes.
      artifact-metadata: write
      attestations: write
      contents: write
      id-token: write`,
  'reusable npm workflow permission ceiling',
);

const stableTagPattern = '^v(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$';
requireText(release, stableTagPattern, 'release stable-tag policy');
requireText(npmPublish, stableTagPattern, 'npm stable-tag policy');

const annotatedTagRefetch = 'refs/tags/${RELEASE_TAG}:refs/tags/${RELEASE_TAG}';
requireText(release, annotatedTagRefetch, 'release annotated-tag restoration');
requireText(npmPublish, annotatedTagRefetch, 'npm annotated-tag restoration');

requireText(release, "requireNewer(candidate, release.tag_name, 'current GitHub latest')", 'GitHub latest monotonicity');
requireText(release, 'requireNewer(candidate, latest.version, `${name} npm latest`)', 'npm latest monotonicity');
requireText(release, 'actual_digest', 'Docker digest verification');
requireText(release, '"sqlite-latest"', 'SQLite moving-alias verification');
requireText(release, '"psql-latest"', 'PostgreSQL moving-alias verification');
requireText(release, '"mysql-latest"', 'MySQL moving-alias verification');
requireText(release, 'GH_REPO: ${{ github.repository }}', 'checkout-free finalization repository binding');
requireText(release, 'run: gh release edit "${RELEASE_TAG}" --draft=false --latest', 'draft-only finalization');

requireText(npmPublish, '--provenance --ignore-scripts', 'npm artifact-only publication');
requireText(npmPublish, "if: inputs.mode == 'publish'", 'npm privileged-mode guard');
requireText(
  npmPublish,
  '--access public --dry-run --ignore-scripts --tag next',
  'npm prerelease dry-run dist-tag isolation',
);

console.log('Release publication policy passed.');
