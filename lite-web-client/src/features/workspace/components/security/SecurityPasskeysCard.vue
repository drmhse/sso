<template>
  <section class="workspace-card stack">
    <div class="section-header">
      <div>
        <h2 class="section-title">Passkeys</h2>
        <p class="section-copy">Register hardware-backed or platform passkeys for passwordless sign-in.</p>
      </div>
      <button type="button" class="text-link text-link--strong" @click="$emit('register')">
        Add Passkey
      </button>
    </div>

    <div v-if="passkeys.length === 0" class="workspace-empty-state">
      <p class="section-copy">No passkeys are registered.</p>
    </div>

    <div v-else class="resource-list">
      <article v-for="passkey in passkeys" :key="passkey.id" class="resource-row">
        <div>
          <div class="resource-row__title">{{ passkey.name }}</div>
          <div class="resource-row__meta">Registered {{ formatDateTime(passkey.created_at) }}</div>
        </div>

        <div class="resource-row__actions">
          <button type="button" class="text-link" @click="$emit('rename', passkey)">Rename</button>
          <button type="button" class="icon-button icon-button--danger" aria-label="Delete passkey" @click="$emit('delete', passkey)">
            <Trash2 class="icon-button__icon" />
          </button>
        </div>
      </article>
    </div>
  </section>
</template>

<script setup>
import { Trash2 } from '@lucide/vue';
import { formatDateTime } from '@/utils/formatting';

defineProps({
  passkeys: { type: Array, default: () => [] },
});

defineEmits(['register', 'rename', 'delete']);
</script>
