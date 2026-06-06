<template>
  <ConfigSection
    title="Billing"
    description="Optional billing provider credentials. These stay file-backed and survive service reloads."
  >
    <div class="form-grid">
      <div class="field">
        <label for="billing-provider">Provider</label>
        <select id="billing-provider" v-model="section.provider" class="input">
          <option value="none">None</option>
          <option value="stripe">Stripe</option>
          <option value="polar">Polar</option>
        </select>
      </div>
      <label v-if="section.provider === 'stripe'" class="checkbox-field align-end">
        <input v-model="section.stripeWebhookTestMode" type="checkbox" />
        <span>Stripe webhook test mode</span>
      </label>
      <div v-if="section.provider === 'stripe'" class="field form-grid-span">
        <label for="billing-secret-key">Stripe secret key</label>
        <input id="billing-secret-key" v-model="section.stripeSecretKey" class="input code" />
      </div>
      <div v-if="section.provider === 'stripe'" class="field form-grid-span">
        <label for="billing-webhook-secret">Stripe webhook secret</label>
        <input id="billing-webhook-secret" v-model="section.stripeWebhookSecret" class="input code" />
      </div>
      <div v-if="section.provider === 'stripe'" class="field form-grid-span">
        <label for="billing-stripe-api-base-url">Stripe API base URL</label>
        <input id="billing-stripe-api-base-url" v-model="section.stripeApiBaseUrl" class="input code" />
      </div>
      <div v-if="section.provider === 'polar'" class="field form-grid-span">
        <label for="billing-polar-api-key">Polar API key</label>
        <input id="billing-polar-api-key" v-model="section.polarApiKey" class="input code" />
      </div>
      <div v-if="section.provider === 'polar'" class="field form-grid-span">
        <label for="billing-polar-webhook-secret">Polar webhook secret</label>
        <input id="billing-polar-webhook-secret" v-model="section.polarWebhookSecret" class="input code" />
      </div>
      <div v-if="section.provider === 'polar'" class="field form-grid-span">
        <label for="billing-polar-api-base-url">Polar API base URL</label>
        <input id="billing-polar-api-base-url" v-model="section.polarApiBaseUrl" class="input code" />
      </div>
    </div>
  </ConfigSection>
</template>

<script setup>
import ConfigSection from './ConfigSection.vue';

const section = defineModel('section', { type: Object, required: true });
</script>
