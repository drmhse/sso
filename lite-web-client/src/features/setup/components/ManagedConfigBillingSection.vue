<template>
  <ConfigSection
    title="Billing"
    description="Optional billing provider credentials. These stay file-backed and survive service reloads."
  >
    <div class="form-grid">
      <div class="field">
        <label for="billing-provider">Provider</label>
        <select id="billing-provider" v-model="section.provider" class="input">
          <option value="stripe">Stripe</option>
          <option value="none">None</option>
        </select>
      </div>
      <label class="checkbox-field align-end">
        <input v-model="section.stripeWebhookTestMode" type="checkbox" />
        <span>Stripe webhook test mode</span>
      </label>
      <div class="field form-grid-span">
        <label for="billing-secret-key">Stripe secret key</label>
        <input id="billing-secret-key" v-model="section.stripeSecretKey" class="input code" />
      </div>
      <div class="field form-grid-span">
        <label for="billing-webhook-secret">Stripe webhook secret</label>
        <input id="billing-webhook-secret" v-model="section.stripeWebhookSecret" class="input code" />
      </div>
    </div>
  </ConfigSection>
</template>

<script setup>
import ConfigSection from './ConfigSection.vue';

const section = defineModel('section', { type: Object, required: true });
</script>
