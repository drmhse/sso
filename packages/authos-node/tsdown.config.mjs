import { defineConfig } from 'tsdown';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    express: 'src/express/index.ts',
  },
  format: ['cjs', 'esm'],
  dts: true,
  clean: true,
  fixedExtension: false,
  deps: {
    neverBundle: ['express'],
    dts: {
      neverBundle: ['express'],
    },
  },
  treeshake: true,
  splitting: false,
});
