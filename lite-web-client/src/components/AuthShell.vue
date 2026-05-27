<template>
  <div class="auth-shell">
    <div class="auth-shell__inner">
      <LiteBrand :title="brandTitle" :tagline="brandTagline" />

      <div v-if="title || description" class="auth-shell__copy">
        <p v-if="eyebrow" class="auth-shell__eyebrow">{{ eyebrow }}</p>
        <h1 v-if="title" class="auth-shell__title">{{ title }}</h1>
        <p v-if="description" class="auth-shell__description">{{ description }}</p>
      </div>

      <section class="auth-panel" :class="panelClass">
        <slot />
      </section>

      <slot name="after" />
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue';
import LiteBrand from '@/components/LiteBrand.vue';

const props = defineProps({
  title: { type: String, default: '' },
  description: { type: String, default: '' },
  eyebrow: { type: String, default: '' },
  panelWidth: { type: String, default: 'md' },
  brandTitle: { type: String, default: 'AuthOS Lite' },
  brandTagline: { type: String, default: 'Secure access management gateway' },
});

const panelClass = computed(() => `auth-panel--${props.panelWidth}`);
</script>
