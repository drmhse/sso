<template>
  <ConfigSection
    title="Platform owner"
    description="This bootstrap account receives the one-time login link and manages the single-org AuthOS deployment."
  >
    <div class="form-grid">
      <div class="field">
        <label for="platform-owner-email">Owner email</label>
        <input id="platform-owner-email" v-model="section.email" type="email" class="input" />
      </div>
      <div class="field">
        <label for="platform-owner-password">Owner password override</label>
        <input id="platform-owner-password" v-model="section.password" type="password" class="input" placeholder="Leave blank to keep generated secret" />
      </div>
    </div>
  </ConfigSection>
</template>

<script setup>
import ConfigSection from './ConfigSection.vue';

const section = defineModel('section', { type: Object, required: true });
</script>
