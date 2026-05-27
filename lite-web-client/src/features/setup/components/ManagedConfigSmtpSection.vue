<template>
  <ConfigSection
    title="Email"
    description="Hosted sign-up, verification, password reset, invitations, and magic links require SMTP delivery."
  >
    <div class="form-grid">
      <div class="field">
        <label for="smtp-mode">SMTP mode</label>
        <select id="smtp-mode" v-model="section.mode" class="input">
          <option value="smtp">SMTP</option>
          <option value="disabled">Disabled</option>
        </select>
      </div>
      <div v-if="section.mode === 'smtp'" class="field">
        <label for="smtp-host">SMTP host</label>
        <input id="smtp-host" v-model="section.host" class="input" placeholder="smtp.example.com" />
      </div>
      <div v-if="section.mode === 'smtp'" class="field">
        <label for="smtp-port">SMTP port</label>
        <input id="smtp-port" v-model.number="section.port" type="number" min="1" max="65535" class="input" />
      </div>
      <div v-if="section.mode === 'smtp'" class="field">
        <label for="smtp-username">SMTP username</label>
        <input id="smtp-username" v-model="section.username" class="input" autocomplete="username" />
      </div>
      <div v-if="section.mode === 'smtp'" class="field">
        <label for="smtp-password">SMTP password</label>
        <input id="smtp-password" v-model="section.password" type="password" class="input" autocomplete="current-password" />
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
