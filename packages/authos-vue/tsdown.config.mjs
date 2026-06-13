import { defineConfig } from 'tsdown';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    nuxt: 'src/nuxt/index.ts',
  },
  format: ['cjs', 'esm'],
  dts: true,
  clean: true,
  fixedExtension: false,
  deps: {
    neverBundle: ['vue', 'nuxt', 'nuxt/app', '@nuxt/kit', '@drmhse/sso-sdk'],
    dts: {
      neverBundle: ['vue', 'nuxt', 'nuxt/app', '@nuxt/kit', '@drmhse/sso-sdk'],
    },
  },
  treeshake: true,
});
