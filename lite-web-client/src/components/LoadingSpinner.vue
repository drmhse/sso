<template>
  <div class="stack" style="justify-items: center; padding: 24px;">
    <div class="spinner"></div>
    <div v-if="text" class="muted">{{ text }}</div>
  </div>
</template>

<script setup>
defineProps({
  text: { type: String, default: '' },
});
</script>
