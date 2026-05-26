<template>
  <ConfigSection
    title="Applications"
    description="Define the organization and application records that bootstrap should provision or update idempotently."
  >
    <div class="split-header">
      <div class="muted">Each application entry provisions one organization, one service, redirect URIs, and any requested API keys.</div>
      <BaseButton variant="secondary" @click="addService">Add application</BaseButton>
    </div>

    <div class="stack">
      <ManagedConfigServiceCard
        v-for="(service, index) in section"
        :key="`${service.org || 'org'}-${service.service || index}`"
        v-model:service="section[index]"
        :index="index"
        @remove="removeService(index)"
      />
    </div>
  </ConfigSection>
</template>

<script setup>
import BaseButton from '@/components/BaseButton.vue';
import { createEmptyService } from '@/features/setup/config';
import ConfigSection from './ConfigSection.vue';
import ManagedConfigServiceCard from './ManagedConfigServiceCard.vue';

const section = defineModel('section', { type: Array, required: true });

function addService() {
  section.value.push(createEmptyService());
}

function removeService(index) {
  section.value.splice(index, 1);
}
</script>
