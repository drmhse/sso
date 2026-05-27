<template>
  <section class="workspace-card stack workspace-card--centered">
    <div class="usage-orb">
      <Zap aria-hidden="true" />
    </div>
    <div class="usage-metric">{{ service?.subscription_count || 0 }}</div>
    <div class="usage-label">Active subscriptions</div>
    <div class="muted usage-copy">
      {{ usage.current_services }} / {{ usage.max_services || usage.current_services }} apps used
      <span v-if="usage.tier">({{ usage.tier }})</span>
    </div>
  </section>
</template>

<script setup>
import { Zap } from '@lucide/vue';

defineProps({
  usage: {
    type: Object,
    default: () => ({
      current_services: 0,
      max_services: 0,
      tier: '',
    }),
  },
  service: { type: Object, default: null },
});
</script>
