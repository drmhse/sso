<template>
  <div class="subsection">
    <div class="split-header">
      <div>
        <h4>API key {{ index + 1 }}</h4>
        <p class="muted">Provisioned service credentials for server-side integrations.</p>
      </div>
      <BaseButton variant="secondary" @click="$emit('remove')">Remove key</BaseButton>
    </div>

    <div class="form-grid">
      <div class="field">
        <label :for="`api-key-name-${index}`">Name</label>
        <input :id="`api-key-name-${index}`" v-model="apiKey.name" class="input" />
      </div>
      <div class="field">
        <label :for="`api-key-write-to-${index}`">Write to</label>
        <input :id="`api-key-write-to-${index}`" v-model="apiKey.writeTo" class="input code" />
      </div>
    </div>

    <StringListField
      :id="`api-key-permissions-${index}`"
      v-model="apiKey.permissions"
      label="Permissions"
      placeholder="read:provider_tokens:github"
      hint="One permission per line."
    />
  </div>
</template>

<script setup>
import BaseButton from '@/components/BaseButton.vue';
import StringListField from './StringListField.vue';

const apiKey = defineModel('apiKey', { type: Object, required: true });

defineProps({
  index: { type: Number, required: true },
});

defineEmits(['remove']);
</script>
