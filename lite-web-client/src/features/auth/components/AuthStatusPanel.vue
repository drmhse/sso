<template>
  <div class="stack auth-status-panel">
    <LoadingSpinner v-if="status === 'loading'" :text="loadingText" />
    <div v-else-if="status === 'success'" class="alert alert-success">{{ successText }}</div>
    <div v-else class="alert alert-error">{{ errorText }}</div>
  </div>
</template>

<script setup>
import LoadingSpinner from '@/components/LoadingSpinner.vue';

defineProps({
  status: { type: String, default: 'loading' },
  loadingText: { type: String, default: '' },
  successText: { type: String, default: '' },
  errorText: { type: String, default: '' },
});
</script>
