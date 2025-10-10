<template>
  <BaseModal
    :is-open="open"
    :title="title"
    size="sm"
    :cancel-text="cancelText"
    :confirm-text="confirmText"
    confirm-variant="danger"
    @close="$emit('cancel')"
    @confirm="$emit('confirm')"
  >
    <p class="text-sm text-gray-500">
      {{ message }}
    </p>
  </BaseModal>
</template>

<script setup>
import BaseModal from './BaseModal.vue';

defineProps({
  open: {
    type: Boolean,
    required: true,
  },
  title: {
    type: String,
    required: true,
  },
  message: {
    type: String,
    required: true,
  },
  confirmText: {
    type: String,
    default: 'Confirm',
  },
  cancelText: {
    type: String,
    default: 'Cancel',
  },
});

defineEmits(['confirm', 'cancel']);
</script>
