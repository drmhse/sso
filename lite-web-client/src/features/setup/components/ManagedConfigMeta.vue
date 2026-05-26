<template>
  <div class="meta-grid">
    <div class="meta-item">
      <div class="meta-label">Config file</div>
      <div class="meta-value code">{{ configPath || 'Unavailable' }}</div>
    </div>
    <div class="meta-item">
      <div class="meta-label">Last apply status</div>
      <div class="meta-value">
        <span class="status-pill" :class="statusClass">{{ statusLabel }}</span>
      </div>
    </div>
    <div class="meta-item">
      <div class="meta-label">Updated</div>
      <div class="meta-value">{{ statusUpdatedAt }}</div>
    </div>
  </div>
</template>

<script setup>
defineProps({
  configPath: { type: String, default: '' },
  statusLabel: { type: String, default: 'idle' },
  statusClass: { type: String, default: '' },
  statusUpdatedAt: { type: String, default: 'Never' },
});
</script>
