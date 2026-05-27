<template>
  <section class="workspace-card stack">
    <div class="section-header">
      <div>
        <h2 class="section-title">Application Configuration</h2>
        <p class="section-copy">Update the public-facing settings used by the selected AuthOS application.</p>
      </div>
    </div>

    <div v-if="services.length > 1" class="field">
      <label for="service-picker">Application</label>
      <select
        id="service-picker"
        :value="selectedServiceSlug"
        class="input"
        @change="$emit('update:selectedServiceSlug', $event.target.value)"
      >
        <option v-for="service in services" :key="service.slug" :value="service.slug">
          {{ service.name }} ({{ service.slug }})
        </option>
      </select>
    </div>

    <div class="field">
      <label for="service-name">Application Name</label>
      <input
        id="service-name"
        :value="serviceName"
        class="input"
        :disabled="!canManage"
        @input="$emit('update:serviceName', $event.target.value)"
      />
    </div>

    <div class="field">
      <div class="field-header">
        <label for="redirect-uris">Approved Redirect URLs</label>
        <span class="field-hint">Must match exactly to prevent routing attacks</span>
      </div>
      <textarea
        id="redirect-uris"
        :value="redirectUrisText"
        class="textarea code"
        :disabled="!canManage"
        @input="$emit('update:redirectUrisText', $event.target.value)"
      />
    </div>

    <div class="field">
      <label for="device-activation-uri">Custom Device Activation URL</label>
      <input
        id="device-activation-uri"
        :value="deviceActivationUri"
        class="input code"
        placeholder="Optional"
        :disabled="!canManage"
        @input="$emit('update:deviceActivationUri', $event.target.value)"
      />
    </div>

    <BaseButton :loading="saving" :disabled="!canManage" @click="$emit('save')">
      Save Changes
    </BaseButton>

    <p v-if="!canManage" class="muted">This session can inspect application settings but cannot change them.</p>
  </section>
</template>

<script setup>
import BaseButton from '@/components/BaseButton.vue';

defineProps({
  services: { type: Array, default: () => [] },
  selectedServiceSlug: { type: String, default: '' },
  serviceName: { type: String, default: '' },
  redirectUrisText: { type: String, default: '' },
  deviceActivationUri: { type: String, default: '' },
  saving: { type: Boolean, default: false },
  canManage: { type: Boolean, default: false },
});

defineEmits([
  'update:selectedServiceSlug',
  'update:serviceName',
  'update:redirectUrisText',
  'update:deviceActivationUri',
  'save',
]);
</script>
