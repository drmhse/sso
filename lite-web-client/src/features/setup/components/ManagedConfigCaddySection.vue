<template>
  <ConfigSection
    title="Proxy and TLS"
    description="Optional Caddy setup for single-binary deployments and clean public URLs."
  >
    <div class="toggle-grid">
      <label class="checkbox-field">
        <input v-model="section.enabled" type="checkbox" />
        <span>Enable Caddy reverse proxy</span>
      </label>
    </div>

    <div class="muted">Package installation remains a local-admin action through the standalone installer.</div>

    <div class="form-grid">
      <div class="field">
        <label for="caddy-domain">Public domain</label>
        <input id="caddy-domain" v-model="section.domain" class="input code" placeholder="auth.example.com" />
      </div>
      <div class="field">
        <label for="caddy-email">ACME email</label>
        <input id="caddy-email" v-model="section.email" type="email" class="input" placeholder="ops@example.com" />
      </div>
      <div class="field">
        <label for="caddy-tls">TLS mode</label>
        <select id="caddy-tls" v-model="section.tls" class="input">
          <option value="auto">Automatic HTTPS</option>
          <option value="internal">Internal CA</option>
          <option value="disabled">Disabled</option>
        </select>
      </div>
    </div>
  </ConfigSection>
</template>

<script setup>
import ConfigSection from './ConfigSection.vue';

const section = defineModel('section', { type: Object, required: true });
</script>
