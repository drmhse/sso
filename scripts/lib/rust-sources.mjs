// Single source of truth for "where the Rust code lives". The api/ tree is a
// cargo workspace: the top crate is api/src, each layer crate is
// api/crates/<name>/src. Policy checks must scan all of them, never just api/src.
import { readdirSync, statSync } from 'node:fs';
import path from 'node:path';

export const REPO_ROOT = path.resolve(import.meta.dirname, '..', '..');

export function rustSourceRoots(root = REPO_ROOT) {
  const roots = [path.join(root, 'api', 'src')];
  const cratesDir = path.join(root, 'api', 'crates');
  let entries = [];
  try {
    entries = readdirSync(cratesDir);
  } catch {
    return roots;
  }
  for (const entry of entries) {
    const candidate = path.join(cratesDir, entry, 'src');
    try {
      if (statSync(candidate).isDirectory()) roots.push(candidate);
    } catch { /* not a crate directory */ }
  }
  return roots;
}

export function rustFiles(root = REPO_ROOT) {
  const out = [];
  const walk = (dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(p);
      else if (entry.name.endsWith('.rs')) out.push(p);
    }
  };
  for (const r of rustSourceRoots(root)) walk(r);
  return out;
}

// The entities crate holds the sea-orm models that used to live in api/src/entities.
export function entitiesDir(root = REPO_ROOT) {
  return path.join(root, 'api', 'crates', 'authos-entities', 'src', 'entities');
}
