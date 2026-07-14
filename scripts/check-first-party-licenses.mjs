#!/usr/bin/env node

import { readFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = new URL('../', import.meta.url);
const rootPath = fileURLToPath(root);

async function text(path) {
  return readFile(new URL(path, root), 'utf8');
}

async function json(path) {
  return JSON.parse(await text(path));
}

function requireValue(actual, expected, label) {
  if (actual !== expected) {
    throw new Error(`${label}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
  }
}

const repositoryLicense = await text('LICENSE');
for (const row of [
  '| `api/` | GNU Affero General Public License v3.0 only |',
  '| `lite-web-client/` | GNU Affero General Public License v3.0 only |',
  '| `scripts/` and `install.sh` | GNU Affero General Public License v3.0 only |',
]) {
  if (!repositoryLicense.includes(row)) {
    throw new Error(`LICENSE is missing policy row: ${row}`);
  }
}

for (const manifest of ['api/Cargo.toml', 'api/migration/Cargo.toml']) {
  const cargo = await text(manifest);
  if (!/^license = "AGPL-3\.0-only"$/mu.test(cargo)) {
    throw new Error(`${manifest} must declare AGPL-3.0-only`);
  }
}

requireValue(await text('api/LICENSE'), await text('LICENSES/AGPL-3.0.txt'), 'API license text');

const dockerfile = await text('api/Dockerfile');
if (!dockerfile.includes('LICENSE /usr/share/licenses/authos/AGPL-3.0.txt')) {
  throw new Error('runtime container omits the complete AGPL license text');
}

requireValue((await json('lite-web-client/package.json')).license, 'AGPL-3.0-only', 'lite-web-client license');

for (const manifest of [
  'sso-sdk/package.json',
  'packages/authos-cli/package.json',
  'packages/authos-node/package.json',
  'packages/authos-react/package.json',
  'packages/authos-vue/package.json',
]) {
  requireValue((await json(manifest)).license, 'MIT', `${manifest} license`);
  requireValue(await text(manifest.replace('package.json', 'LICENSE')), await text('LICENSES/MIT.txt'), `${manifest} license text`);

  const packageDirectory = manifest.replace('/package.json', '');
  const packed = JSON.parse(execFileSync(
    'npm',
    ['pack', '--dry-run', '--json', '--ignore-scripts', `./${packageDirectory}`],
    { cwd: rootPath, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
  ));
  if (!packed[0]?.files?.some((entry) => entry.path === 'LICENSE')) {
    throw new Error(`${manifest} packed artifact omits LICENSE`);
  }
}

const bundleBuilder = await text('scripts/authos-bootstrap/build-binary.js');
for (const notice of ["path.join(ROOT, 'LICENSE')", "path.join(ROOT, 'LICENSES/AGPL-3.0.txt')"]) {
  if (!bundleBuilder.includes(notice)) {
    throw new Error(`standalone bundle omits ${notice}`);
  }
}
const standaloneManager = await text('scripts/authos-standalone/authos_standalone.py');
if (!standaloneManager.includes('for notice in ("LICENSE", "AGPL-3.0.txt", "README.txt")')) {
  throw new Error('standalone installation does not retain its license and source-offer notices');
}
if (!bundleBuilder.includes('Corresponding source: https://github.com/drmhse/AuthOS/tree/${buildVersion}')) {
  throw new Error('standalone bundle omits its exact corresponding-source location');
}
if (!bundleBuilder.includes("path.join(ROOT, 'scripts/authos-standalone/authos.config.example.json')")) {
  throw new Error('standalone bundle must source its example config from the AGPL-licensed scripts path');
}

const standaloneExample = await json('scripts/authos-standalone/authos.config.example.json');
requireValue(standaloneExample.deployment?.backend, 'sqlite', 'standalone example backend');
if (!Array.isArray(standaloneExample.services)) {
  throw new Error('standalone example services must be an array');
}

for (const executable of ['install.sh', 'scripts/authos-standalone/install.sh', 'scripts/authos-standalone/authos_standalone.py']) {
  if (!(await text(executable)).includes('SPDX-License-Identifier: AGPL-3.0-only')) {
    throw new Error(`${executable} is missing its AGPL SPDX identifier`);
  }
}

console.log('First-party license policy passed.');
