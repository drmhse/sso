import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';

import { rustSourceRoots } from './lib/rust-sources.mjs';

const root = path.resolve(import.meta.dirname, '..');
const matrixPath = path.join(root, 'docs/security/tenant-isolation-matrix.json');
const matrix = JSON.parse(fs.readFileSync(matrixPath, 'utf8'));

if (matrix.version !== 1 || matrix.status !== 'partial-local-evidence') {
  throw new Error('tenant isolation matrix must be version 1 and explicitly partial');
}
if (!Array.isArray(matrix.resources) || matrix.resources.length === 0) {
  throw new Error('tenant isolation matrix requires resource rows');
}

const inventory = fs.readFileSync(path.join(root, matrix.sources.inventory), 'utf8');
const router = fs.readFileSync(path.join(root, matrix.sources.router), 'utf8');
const main = fs.readFileSync(path.join(root, matrix.sources.main), 'utf8');
const entityDir = path.join(root, matrix.sources.entities);
const entityTables = new Set();
const rustSources = [];
for (const file of fs.readdirSync(entityDir).filter((name) => name.endsWith('.rs'))) {
  const source = fs.readFileSync(path.join(entityDir, file), 'utf8');
  for (const match of source.matchAll(/#\[sea_orm\(table_name = "([^"]+)"\)\]/g)) {
    entityTables.add(match[1]);
  }
}
function collectRustSources(directory) {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const entryPath = path.join(directory, entry.name);
    if (entry.isDirectory()) collectRustSources(entryPath);
    if (entry.isFile() && entry.name.endsWith('.rs')) {
      rustSources.push(fs.readFileSync(entryPath, 'utf8'));
    }
  }
}
for (const dir of rustSourceRoots(root)) collectRustSources(dir);
const allRust = rustSources.join('\n');
const routes = new Set(
  [router, main].flatMap((source) =>
    [...source.matchAll(/\.route\(\s*"([^"]+)"/g)].map((match) => match[1]),
  ),
);

const recordedEntities = new Map();
let openCriticalHigh = 0;
for (const resource of matrix.resources) {
  for (const field of ['name', 'scope', 'criticality', 'tenant_selector']) {
    if (typeof resource[field] !== 'string' || resource[field].trim() === '') {
      throw new Error(`matrix row has invalid ${field}: ${JSON.stringify(resource)}`);
    }
  }
  if (!['critical', 'high', 'medium', 'low'].includes(resource.criticality)) {
    throw new Error(`matrix row ${resource.name} has invalid criticality`);
  }
  if (!Array.isArray(resource.inventory_refs) || resource.inventory_refs.length === 0) {
    throw new Error(`matrix row ${resource.name} has no inventory_refs`);
  }
  for (const reference of resource.inventory_refs) {
    if (!inventory.includes(reference)) {
      throw new Error(`matrix row ${resource.name} has stale inventory ref: ${reference}`);
    }
  }
  if (!Array.isArray(resource.entities) || !Array.isArray(resource.route_patterns)) {
    throw new Error(`matrix row ${resource.name} requires entities and route_patterns arrays`);
  }
  if (!Array.isArray(resource.sqlite_evidence) || !Array.isArray(resource.open_gaps)) {
    throw new Error(`matrix row ${resource.name} requires evidence and explicit open gaps`);
  }
  for (const evidence of resource.sqlite_evidence) {
    const testName = evidence.split('::').at(-1);
    if (!testName || !new RegExp(`(?:async\\s+)?fn\\s+${testName}\\s*\\(`).test(allRust)) {
      throw new Error(`matrix row ${resource.name} references missing SQLite test: ${evidence}`);
    }
  }
  if (resource.open_gaps.length === 0) {
    throw new Error(`matrix row ${resource.name} must not claim closure without three-database evidence`);
  }
  for (const gap of resource.open_gaps) {
    if (!/^(critical|high|medium|low): /.test(gap)) {
      throw new Error(`matrix row ${resource.name} has unclassified gap: ${gap}`);
    }
    if (/^(critical|high): /.test(gap)) openCriticalHigh += 1;
  }
  for (const table of resource.entities) {
    if (recordedEntities.has(table)) {
      throw new Error(`entity ${table} is assigned to both ${recordedEntities.get(table)} and ${resource.name}`);
    }
    recordedEntities.set(table, resource.name);
  }
  for (const pattern of resource.route_patterns) {
    // Compile now so malformed expressions fail in CI even if no current route reaches them.
    new RegExp(pattern);
  }
}

const missingEntities = [...entityTables].filter((table) => !recordedEntities.has(table)).sort();
const staleEntities = [...recordedEntities.keys()].filter((table) => !entityTables.has(table)).sort();
const missingProseEntities = [...entityTables]
  .filter((table) => !inventory.includes(`\`${table}\``))
  .sort();
if (missingEntities.length > 0 || staleEntities.length > 0 || missingProseEntities.length > 0) {
  throw new Error(`tenant entity inventory mismatch; missing=${JSON.stringify(missingEntities)}, stale=${JSON.stringify(staleEntities)}, missingFromProse=${JSON.stringify(missingProseEntities)}`);
}

const unmatchedRoutes = [];
const multiplyMatchedRoutes = [];
for (const route of routes) {
  const matches = matrix.resources.filter((resource) =>
    resource.route_patterns.some((pattern) => new RegExp(pattern).test(route)),
  );
  if (matches.length === 0) unmatchedRoutes.push(route);
  if (matches.length > 1) multiplyMatchedRoutes.push([route, matches.map((row) => row.name)]);
}
if (unmatchedRoutes.length > 0 || multiplyMatchedRoutes.length > 0) {
  throw new Error(
    `tenant route inventory mismatch; unmatched=${JSON.stringify(unmatchedRoutes.sort())}, multiplyMatched=${JSON.stringify(multiplyMatchedRoutes)}`,
  );
}

console.log(
  `Tenant isolation matrix is structurally complete but explicitly partial: ${matrix.resources.length} resource rows, ${entityTables.size} entities, ${routes.size} routes, ${openCriticalHigh} tracked critical/high gaps.`,
);
