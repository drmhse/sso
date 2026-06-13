import { defineConfig } from 'tsdown';

export default defineConfig([
  // Library entry (no shebang)
  {
    entry: { index: 'src/index.ts' },
    format: ['cjs'],
    dts: true,
    clean: true,
    treeshake: true,
    splitting: false,
    fixedExtension: false,
  },
  // CLI binary entry (with shebang)
  {
    entry: { bin: 'src/bin.ts' },
    format: ['cjs'],
    dts: true,
    treeshake: true,
    splitting: false,
    fixedExtension: false,
    banner: {
      js: '#!/usr/bin/env node',
    },
  },
]);
