import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

test('React and Next.js ESM exports load without bundled framework internals', async () => {
  const react = await import('../dist/index.mjs');
  const nextjs = await import('../dist/nextjs.mjs');
  const source = await readFile(new URL('../dist/nextjs.mjs', import.meta.url), 'utf8');

  assert.equal(typeof react.AuthOSProvider, 'function');
  for (const name of ['authMiddleware', 'currentUser', 'auth', 'getToken']) {
    assert.equal(typeof nextjs[name], 'function', `missing ${name}`);
  }
  assert.doesNotMatch(source, /node_modules\/next/);
  assert.doesNotMatch(source, /\b__dirname\b/);
});
