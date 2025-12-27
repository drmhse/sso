import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    nuxt: 'src/nuxt/index.ts',
  },
  format: ['cjs', 'esm'],
  dts: true,
  clean: true,
  external: ['vue', 'nuxt', '@drmhse/sso-sdk'],
  treeshake: true,
});
