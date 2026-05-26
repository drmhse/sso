<template>
  <section class="stack">
    <div>
      <h3>{{ title }}</h3>
      <p v-if="description" class="muted">{{ description }}</p>
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
