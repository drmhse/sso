#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { rustSourceRoots } from './lib/rust-sources.mjs';

const root = path.resolve(import.meta.dirname, '..');
// Every workspace crate, not just the top one.
const sourceRoots = rustSourceRoots(root);
const macroPattern = /tracing::(?:trace|debug|info|warn|error)!\(/g;
const sensitiveIdentifier =
  /(?:^|[^A-Za-z0-9_])(?:[A-Za-z0-9_]+\.)?(?:[A-Za-z0-9_]+_)?(?:email|password|access_token|refresh_token|client_secret|api_key|authorization|cookie|secret)(?:[^A-Za-z0-9_]|$)/;

export function maskLiterals(source) {
  const masked = [...source];
  for (let index = 0; index < source.length; index += 1) {
    if (source.startsWith('//', index)) {
      while (index < source.length && source[index] !== '\n') masked[index++] = ' ';
      continue;
    }
    if (source.startsWith('/*', index)) {
      let depth = 1;
      masked[index++] = ' ';
      masked[index] = ' ';
      while (++index < source.length && depth > 0) {
        if (source.startsWith('/*', index)) depth += 1;
        if (source.startsWith('*/', index)) depth -= 1;
        if (source[index] !== '\n') masked[index] = ' ';
      }
      continue;
    }

    const raw = source.slice(index).match(/^r(#+)?"/);
    if (raw) {
      const hashes = raw[1] ?? '';
      const terminator = `"${hashes}`;
      const end = source.indexOf(terminator, index + raw[0].length);
      const final = end === -1 ? source.length - 1 : end + terminator.length - 1;
      for (; index <= final; index += 1) if (source[index] !== '\n') masked[index] = ' ';
      index -= 1;
      continue;
    }

    if (source[index] === '"') {
      masked[index] = ' ';
      while (++index < source.length) {
        if (source[index] !== '\n') masked[index] = ' ';
        if (source[index] === '"' && source[index - 1] !== '\\') break;
      }
    }
  }
  return masked.join('');
}

function rustFiles(directory) {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const target = path.join(directory, entry.name);
    if (entry.isDirectory()) return rustFiles(target);
    return entry.isFile() && entry.name.endsWith('.rs') ? [target] : [];
  });
}

export function sensitiveTracingLines(source) {
  const masked = maskLiterals(source);
  const lines = [];
  for (const match of masked.matchAll(macroPattern)) {
    const open = match.index + match[0].length - 1;
    let depth = 1;
    let close = open + 1;
    while (close < masked.length && depth > 0) {
      if (masked[close] === '(') depth += 1;
      if (masked[close] === ')') depth -= 1;
      close += 1;
    }
    if (depth !== 0) throw new Error('unterminated tracing macro');
    const argumentsWithoutLiterals = masked.slice(open + 1, close - 1);
    if (!sensitiveIdentifier.test(argumentsWithoutLiterals)) continue;

    const line = source.slice(0, match.index).split('\n').length;
    lines.push(line);
  }
  return lines;
}

function main() {
  const violations = [];
  for (const file of sourceRoots.flatMap((dir) => rustFiles(dir))) {
    const source = fs.readFileSync(file, 'utf8');
    for (const line of sensitiveTracingLines(source)) {
      violations.push(`${path.relative(root, file)}:${line}`);
    }
  }

  if (violations.length > 0) {
    throw new Error(
      `sensitive identifiers are passed to tracing macros:\n${violations.join('\n')}`,
    );
  }

  console.log('Sensitive logging check passed: tracing macros do not receive credential or email values.');
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
