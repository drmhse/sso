<template>
  <section class="workspace-card stack">
    <div class="section-header">
      <div>
      <h3 class="section-title">{{ title }}</h3>
      <p v-if="description" class="muted">{{ description }}</p>
      </div>
    </div>
    <slot />
  </section>
</template>

<script setup>
defineProps({
  title: { type: String, required: true },
  description: { type: String, default: '' },
});
</script>
