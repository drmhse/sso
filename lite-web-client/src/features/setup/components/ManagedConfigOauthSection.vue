<template>
  <ConfigSection
    title="OAuth providers"
    description="Enable upstream OAuth integrations without leaving the lite admin workspace."
  >
    <div class="stack">
      <div v-for="provider in providers" :key="provider.key" class="subsection">
        <div>
          <h4>{{ provider.label }}</h4>
          <p class="muted">Client credentials for {{ provider.label }} sign-in.</p>
        </div>

        <div class="form-grid">
          <div class="field">
            <label :for="`${provider.key}-client-id`">Client ID</label>
            <input :id="`${provider.key}-client-id`" v-model="section[provider.key].clientId" class="input code" />
          </div>
          <div class="field">
            <label :for="`${provider.key}-client-secret`">Client secret</label>
            <input :id="`${provider.key}-client-secret`" v-model="section[provider.key].clientSecret" class="input code" />
          </div>
        </div>
      </div>
    </div>
  </ConfigSection>
</template>

<script setup>
import ConfigSection from './ConfigSection.vue';

const section = defineModel('section', { type: Object, required: true });

const providers = [
  { key: 'github', label: 'GitHub' },
  { key: 'google', label: 'Google' },
  { key: 'microsoft', label: 'Microsoft' },
];
</script>
