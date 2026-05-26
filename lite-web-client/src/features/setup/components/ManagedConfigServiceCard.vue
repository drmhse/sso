<template>
  <div class="subsection stack">
    <div class="split-header">
      <div>
        <h4>{{ heading }}</h4>
        <p class="muted">Single-org application bootstrap details, including redirect URIs and provisioned API keys.</p>
      </div>
      <BaseButton variant="secondary" @click="$emit('remove')">Remove application</BaseButton>
    </div>

    <div class="form-grid">
      <div class="field">
        <label :for="`service-org-${index}`">Organization slug</label>
        <input :id="`service-org-${index}`" v-model="service.org" class="input code" />
      </div>
      <div class="field">
        <label :for="`service-org-name-${index}`">Organization name</label>
        <input :id="`service-org-name-${index}`" v-model="service.orgName" class="input" />
      </div>
      <div class="field">
        <label :for="`service-slug-${index}`">Application slug</label>
        <input :id="`service-slug-${index}`" v-model="service.service" class="input code" />
      </div>
      <div class="field">
        <label :for="`service-name-${index}`">Application name</label>
        <input :id="`service-name-${index}`" v-model="service.name" class="input" />
      </div>
      <div class="field">
        <label :for="`service-type-${index}`">Application type</label>
        <select :id="`service-type-${index}`" v-model="service.type" class="input">
          <option value="web">Web</option>
          <option value="native">Native</option>
          <option value="spa">SPA</option>
          <option value="machine">Machine</option>
        </select>
      </div>
    </div>

    <StringListField
      :id="`service-redirects-${index}`"
      v-model="service.redirectUris"
      label="Redirect URIs"
      placeholder="https://app.example.com/callback"
      hint="One redirect URI per line."
    />

    <StringListField
      :id="`service-scopes-${index}`"
      v-model="service.githubScopes"
      label="GitHub scopes"
      placeholder="read:user"
      hint="Optional scopes to bootstrap for GitHub-linked services."
    />

    <div class="stack">
      <div class="split-header">
        <div>
          <h4>API keys</h4>
          <p class="muted">Server-side credentials to provision for this application.</p>
        </div>
        <BaseButton variant="secondary" @click="addApiKey">Add API key</BaseButton>
      </div>

      <div v-if="service.apiKeys.length === 0" class="muted">No API keys configured for this application.</div>
      <ServiceApiKeyCard
        v-for="(apiKey, apiKeyIndex) in service.apiKeys"
        :key="`${index}-${apiKeyIndex}`"
        v-model:api-key="service.apiKeys[apiKeyIndex]"
        :index="apiKeyIndex"
        @remove="removeApiKey(apiKeyIndex)"
      />
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue';
import BaseButton from '@/components/BaseButton.vue';
import { createEmptyApiKey } from '@/features/setup/config';
import ServiceApiKeyCard from './ServiceApiKeyCard.vue';
import StringListField from './StringListField.vue';

const service = defineModel('service', { type: Object, required: true });

const props = defineProps({
  index: { type: Number, required: true },
});

defineEmits(['remove']);

const heading = computed(() => service.value.name || `Application ${props.index + 1}`);

function addApiKey() {
  service.value.apiKeys.push(createEmptyApiKey());
}

function removeApiKey(index) {
  service.value.apiKeys.splice(index, 1);
}
</script>
