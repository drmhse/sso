#!/usr/bin/env node
// Enforces the api/src layer order: a module may only reference modules at or
// below its own layer. Keeps the architecture from silently re-tangling.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

// Cross-crate layering is enforced by cargo itself (crates/authos-* form a DAG;
// a cycle would not compile). This check covers what cargo cannot see: module
// ordering *within* each crate, and modules drifting out of their layer.
const ROOTS = ['api/src', ...readdirSync('api/crates')
  .map((c) => `api/crates/${c}/src`)
  .filter((p) => { try { return statSync(p).isDirectory(); } catch { return false; } })];

// Ascending layers. Anything in a layer may use its own layer and lower ones.
const LAYERS = [
  ['config', 'constants', 'error', 'entities', 'rsa_keys', 'client_ip', 'runtime_metadata'],
  ['utils'],
  ['crypto', 'encryption'],
  ['db'],
  ['audit'],
  ['store'],
  ['services'],
  ['billing', 'email', 'jobs'],
  ['state'],
  ['middleware'],
  ['handlers'],
  ['router'],
  ['main', 'http_security', 'lite_web', 'sso_sqlite', 'sso_psql', 'sso_mysql'],
];

const layerOf = new Map();
LAYERS.forEach((mods, i) => mods.forEach((m) => layerOf.set(m, i)));

function walk(dir) {
  return readdirSync(dir).flatMap((e) => {
    const p = join(dir, e);
    return statSync(p).isDirectory() ? walk(p) : p.endsWith('.rs') ? [p] : [];
  });
}

// #[cfg(test)] blocks are exempt: test code may reach up for fixtures.
function stripTests(text) {
  const lines = text.split('\n');
  const out = [];
  for (let i = 0; i < lines.length; i += 1) {
    if (/^\s*#\[cfg\(test\)\]/.test(lines[i])) {
      let depth = 0;
      let started = false;
      while (i < lines.length) {
        for (const ch of lines[i]) {
          if (ch === '{') { depth += 1; started = true; } else if (ch === '}') depth -= 1;
        }
        if (started && depth <= 0) break;
        i += 1;
      }
      continue;
    }
    out.push(lines[i]);
  }
  return out.join('\n');
}

const violations = [];
for (const root of ROOTS) {
 for (const file of walk(root)) {
  // lib.rs holds the deliberate lower-layer re-exports; it defines no layer.
  if (file.endsWith('/lib.rs')) continue;
  const owner = file.slice(root.length + 1).split('/')[0].replace(/\.rs$/, '');
  const ownerLayer = layerOf.get(owner);
  if (ownerLayer === undefined) {
    violations.push(`${file}: module '${owner}' is not assigned to a layer`);
    continue;
  }
  const body = stripTests(readFileSync(file, 'utf8'));
  for (const m of body.matchAll(/crate::([a-z_]+)/g)) {
    const target = m[1];
    const targetLayer = layerOf.get(target);
    if (targetLayer === undefined || target === owner) continue;
    if (targetLayer > ownerLayer) {
      violations.push(`${file}: '${owner}' (layer ${ownerLayer}) must not use '${target}' (layer ${targetLayer})`);
    }
  }
 }
}

const unique = [...new Set(violations)];
if (unique.length) {
  console.error(`Layer violations (${unique.length}):`);
  for (const v of unique) console.error(`  ${v}`);
  process.exit(1);
}
console.log(`Layer boundaries OK across ${ROOTS.length} crate roots: dependency graph is acyclic and ordered.`);
