import assert from 'node:assert/strict';
import test from 'node:test';

test('Node and Express ESM exports load', async () => {
  const node = await import('../dist/index.mjs');
  const express = await import('../dist/express.mjs');

  assert.equal(typeof node.createTokenVerifier, 'function');
  assert.ok(Object.keys(express).length > 0);
});
