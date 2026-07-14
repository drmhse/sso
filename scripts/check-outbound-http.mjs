#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';

const root = path.resolve(import.meta.dirname, '..');
const sourceRoot = path.join(root, 'api', 'src');
const inventoryPath = path.join(root, 'docs', 'security', 'outbound-http-inventory.json');
const rawClientPattern = /reqwest::(?:Client::new|Client::builder|get)\s*\(/;

function rustFiles(directory) {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const target = path.join(directory, entry.name);
    if (entry.isDirectory()) return rustFiles(target);
    return entry.isFile() && entry.name.endsWith('.rs') ? [target] : [];
  });
}

const discovered = rustFiles(sourceRoot)
  .filter((file) => rawClientPattern.test(fs.readFileSync(file, 'utf8')))
  .map((file) => path.relative(root, file).split(path.sep).join('/'))
  .sort();

const inventory = JSON.parse(fs.readFileSync(inventoryPath, 'utf8'));
if (inventory.version !== 1 || !Array.isArray(inventory.entries)) {
  throw new Error('outbound HTTP inventory must use version 1 with an entries array');
}

const allowedClassifications = new Set([
  'central_policy',
  'reviewed_custom',
  'fixed_external_gap',
  'open_gap',
]);
const recorded = [];
for (const [index, entry] of inventory.entries.entries()) {
  for (const field of [
    'path',
    'classification',
    'destination',
    'credentials',
    'response_bound',
    'remediation',
  ]) {
    if (typeof entry[field] !== 'string' || entry[field].trim() === '') {
      throw new Error(`inventory entry ${index} has invalid ${field}`);
    }
  }
  if (!allowedClassifications.has(entry.classification)) {
    throw new Error(`inventory entry ${entry.path} has unknown classification`);
  }
  if (!fs.existsSync(path.join(root, entry.path))) {
    throw new Error(`inventory entry does not exist: ${entry.path}`);
  }
  recorded.push(entry.path);
}
recorded.sort();

if (new Set(recorded).size !== recorded.length) {
  throw new Error('outbound HTTP inventory contains duplicate paths');
}
if (JSON.stringify(discovered) !== JSON.stringify(recorded)) {
  const missing = discovered.filter((file) => !recorded.includes(file));
  const stale = recorded.filter((file) => !discovered.includes(file));
  throw new Error(
    `outbound HTTP inventory mismatch; unrecorded=${JSON.stringify(missing)}, stale=${JSON.stringify(stale)}`,
  );
}

const openGaps = inventory.entries.filter((entry) => entry.classification.endsWith('_gap')).length;
console.log(
  `Outbound HTTP inventory is complete: ${recorded.length} raw-client files, ${openGaps} explicitly tracked gaps.`,
);
