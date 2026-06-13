import { defineConfig } from 'tsdown';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    nextjs: 'src/nextjs/index.ts',
  },
  format: ['cjs', 'esm'],
  dts: true,
  clean: true,
  fixedExtension: false,
  deps: {
    neverBundle: ['react', 'next', '@drmhse/sso-sdk'],
    dts: {
      neverBundle: ['react', 'next', '@drmhse/sso-sdk'],
    },
  },
  inputOptions: {
    external: [/^react(\/.*)?$/, /^next(\/.*)?$/, /^@drmhse\/sso-sdk(\/.*)?$/],
  },
  treeshake: true,
  splitting: false,
});
