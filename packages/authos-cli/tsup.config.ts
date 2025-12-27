import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    bin: 'src/bin.ts',
  },
  format: ['cjs'],
  dts: true,
  clean: true,
  treeshake: true,
  splitting: false,
  banner: {
    js: '#!/usr/bin/env node',
  },
});
