import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

test('Vue exports load and Nuxt keeps framework peers external', async () => {
  const vue = await import('../dist/index.mjs');
  const source = await readFile(new URL('../dist/nuxt.mjs', import.meta.url), 'utf8');

  assert.equal(typeof vue.createAuthOS, 'function');
  for (const name of ['authOSModule', 'authMiddleware', 'createAuthMiddleware']) {
    assert.match(source, new RegExp(`\\b${name}\\b`), `missing ${name}`);
  }
  assert.match(source, /from ["']@nuxt\/kit["']/);
  assert.match(source, /from ["']nuxt\/app["']/);
  assert.doesNotMatch(source, /node_modules\/nuxt/);
});
