<template>
  <section class="workspace-card stack">
    <div class="section-header">
      <div>
        <h2 class="section-title">Trusted Devices</h2>
        <p class="section-copy">Rename or revoke remembered devices tied to this operator account.</p>
      </div>
    </div>

    <div v-if="devices.length === 0" class="workspace-empty-state">
      <p class="section-copy">No trusted devices are registered.</p>
    </div>

    <div v-else class="resource-list">
      <article v-for="device in devices" :key="device.id" class="resource-row">
        <div>
          <div class="resource-row__title">{{ device.device_name }}</div>
          <div class="resource-row__meta">
            Last used {{ formatDateTime(device.last_used_at, 'Never') }} · Risk score {{ device.risk_score }}
          </div>
        </div>

        <div class="resource-row__actions">
          <button type="button" class="text-link" @click="$emit('rename', device)">Rename</button>
          <button type="button" class="icon-button icon-button--danger" aria-label="Revoke device" @click="$emit('revoke', device)">
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
  devices: { type: Array, default: () => [] },
});

defineEmits(['rename', 'revoke']);
</script>
