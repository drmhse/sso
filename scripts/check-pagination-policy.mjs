#!/usr/bin/env node

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

const rootPath = new URL('../api/src/', import.meta.url).pathname;

function rustFiles(directory) {
  return readdirSync(directory).flatMap((entry) => {
    const path = join(directory, entry);
    if (statSync(path).isDirectory()) return rustFiles(path);
    return path.endsWith('.rs') ? [path] : [];
  });
}

const forbidden = [
  ['signed value cast inside SQL limit', /\.limit\([^\n)]*\bas\s+u64\s*\)/g],
  ['signed value cast inside SQL offset', /\.offset\([^\n)]*\bas\s+u64\s*\)/g],
  ['signed value cast inside collection skip', /\.skip\([^\n)]*\bas\s+usize\s*\)/g],
  ['signed value cast inside collection take', /\.take\([^\n)]*\bas\s+usize\s*\)/g],
  [
    'intermediate pagination cast',
    /\b(?:let\s+)?(?:page|limit|offset|start_index|\w+_(?:limit|offset|start_index))\s*(?::[^=\n]+)?=\s*[\s\S]{0,160}?\bas\s+(?:u64|usize)\b/g,
  ],
  [
    'pagination-derived intermediate cast',
    /\blet\s+\w+\s*(?::[^=;\n]+)?=\s*[^;]{0,200}?\b\w*(?:page|limit|offset|start_index)\w*\b[^;]{0,100}?\bas\s+(?:u64|usize)\b/g,
  ],
  ['unchecked one-based page multiplication', /\(\s*page\s*-\s*1\s*\)\s*\*\s*limit/g],
  ['unchecked zero-based page multiplication', /\bpage\s*\*\s*limit\b/g],
];

const negativeControls = [
  'let converted = requested_limit as u64; query.limit(converted);',
  'let offset = page.saturating_mul(limit) as usize; rows.skip(offset);',
  'query.offset(raw_offset as u64);',
];
for (const control of negativeControls) {
  const detected = forbidden.some(([, pattern]) =>
    new RegExp(pattern.source, pattern.flags).test(control),
  );
  if (!detected) {
    console.error(`Pagination policy negative control was not detected: ${control}`);
    process.exit(1);
  }
}

const failures = [];
for (const file of rustFiles(rootPath)) {
  if (file.endsWith('/utils/pagination.rs')) continue;
  const source = readFileSync(file, 'utf8');
  for (const [name, pattern] of forbidden) {
    for (const match of source.matchAll(pattern)) {
      const line = source.slice(0, match.index).split('\n').length;
      failures.push(`${relative(rootPath, file)}:${line}: ${name}: ${match[0]}`);
    }
  }
}

if (failures.length > 0) {
  console.error('Pagination policy violations found:');
  for (const failure of failures) console.error(`- ${failure}`);
  console.error('Normalize signed values and use checked/saturating offset helpers before conversion.');
  process.exit(1);
}

console.log('Pagination policy check passed.');
