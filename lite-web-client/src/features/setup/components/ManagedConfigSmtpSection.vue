<template>
  <ConfigSection
    title="Email"
    description="Configure delivery defaults for verification, invite, and account recovery messages."
  >
    <div class="form-grid">
      <div class="field">
        <label for="smtp-mode">SMTP mode</label>
        <select id="smtp-mode" v-model="section.mode" class="input">
          <option value="mailpit">Mailpit</option>
          <option value="smtp">SMTP</option>
          <option value="disabled">Disabled</option>
        </select>
      </div>
      <div class="field">
        <label for="smtp-from-name">From name</label>
        <input id="smtp-from-name" v-model="section.fromName" class="input" />
      </div>
      <div class="field form-grid-span">
        <label for="smtp-from-email">From email</label>
        <input id="smtp-from-email" v-model="section.fromEmail" type="email" class="input" />
      </div>
    </div>
  </ConfigSection>
</template>

<script setup>
import ConfigSection from './ConfigSection.vue';

const section = defineModel('section', { type: Object, required: true });
</script>
