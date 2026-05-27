<template>
  <section class="workspace-card stack">
    <div class="section-header">
      <div>
        <h2 class="section-title">Organization Profile</h2>
        <p class="section-copy">Update the single organization exposed by AuthOS Lite.</p>
      </div>
    </div>

    <div class="organization-identity">
      <div class="organization-identity__avatar">{{ initials }}</div>
      <div>
        <div class="organization-identity__name">{{ orgName || 'Organization' }}</div>
        <div class="organization-identity__meta">
          Slug: {{ orgSlug || 'n/a' }} · {{ membershipCount }} Active Members · {{ serviceCount }} Apps
        </div>
      </div>
    </div>

    <div class="field">
      <label for="organization-name">Organization Name</label>
      <div class="inline-action-row">
        <input
          id="organization-name"
          :value="orgName"
          class="input"
          :disabled="!canEdit"
          @input="$emit('update:orgName', $event.target.value)"
        />
        <BaseButton :loading="saving" :disabled="!canEdit" @click="$emit('save')">
          Rename
        </BaseButton>
      </div>
    </div>
  </section>
</template>

<script setup>
import { computed } from 'vue';
import BaseButton from '@/components/BaseButton.vue';

const props = defineProps({
  orgName: { type: String, default: '' },
  orgSlug: { type: String, default: '' },
  membershipCount: { type: Number, default: 0 },
  serviceCount: { type: Number, default: 0 },
  canEdit: { type: Boolean, default: false },
  saving: { type: Boolean, default: false },
});

defineEmits(['update:orgName', 'save']);

const initials = computed(() => {
  const text = props.orgName || 'AO';
  return text
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part.charAt(0).toUpperCase())
    .join('');
});
</script>
