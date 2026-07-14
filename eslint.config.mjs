import js from '@eslint/js';
import tsPlugin from '@typescript-eslint/eslint-plugin';
import tsParser from '@typescript-eslint/parser';
import vue from 'eslint-plugin-vue';
import globals from 'globals';

export default [
  {
    ignores: [
      '**/dist/**',
      '**/node_modules/**',
      '.artifacts/**',
      '.authos/**',
      'api/**',
    ],
  },
  {
    files: ['**/*.{js,mjs,cjs,ts,tsx,vue}'],
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
      globals: {
        ...globals.browser,
        ...globals.node,
      },
    },
  },
  js.configs.recommended,
  ...vue.configs['flat/essential'],
  {
    files: [
      '**/*.vue',
      'packages/authos-vue/src/components/{Callback,Protect}.ts',
    ],
    languageOptions: {
      parserOptions: {
        parser: tsParser,
        ecmaVersion: 'latest',
        sourceType: 'module',
      },
    },
    rules: {
      // Entry points and public APIs intentionally include App, Callback, and Protect.
      'vue/multi-word-component-names': 'off',
    },
  },
  {
    files: ['**/*.{ts,tsx}'],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        ecmaFeatures: { jsx: true },
      },
    },
    plugins: {
      '@typescript-eslint': tsPlugin,
    },
    rules: {
      ...tsPlugin.configs.recommended.rules,
      // TypeScript resolves type-only and JSX namespace references itself.
      'no-undef': 'off',
    },
  },
  {
    files: ['sso-sdk/src/**/*.ts'],
    rules: {
      // Legacy SDK extension payloads remain deliberately open while their
      // public types are narrowed in a future compatibility-safe release.
      '@typescript-eslint/no-explicit-any': 'off',
    },
  },
  {
    files: [
      'packages/authos-react/src/components/{Callback,SignIn,SignUp}.tsx',
      'packages/authos-vue/src/components/{Callback,SignIn,SignUp}.ts',
    ],
    rules: {
      // Framework callback errors and provider prop coercion cross untyped
      // runtime boundaries; the surrounding public APIs remain typed.
      '@typescript-eslint/no-explicit-any': 'off',
    },
  },
  {
    files: ['packages/authos-node/src/express/middleware.ts'],
    rules: {
      // Express declaration merging requires augmenting its global namespace.
      '@typescript-eslint/no-namespace': 'off',
    },
  },
];
