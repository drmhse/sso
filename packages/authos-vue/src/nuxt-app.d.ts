declare module 'nuxt/app' {
  import type { App } from 'vue';

  export interface NuxtApp {
    vueApp: App;
  }

  export function defineNuxtPlugin(plugin: (nuxtApp: NuxtApp) => void): unknown;
  export function useRuntimeConfig(): {
    public: Record<string, unknown>;
  };
  export function defineNuxtRouteMiddleware(
    middleware: () => unknown,
  ): unknown;
  export function navigateTo(
    path: string,
    options?: { redirectCode?: number; replace?: boolean },
  ): unknown;
}
