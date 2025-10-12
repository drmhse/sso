<template>
  <BaseModal
    :is-open="open"
    :title="title"
    size="sm"
    :cancel-text="cancelText"
    :confirm-text="confirmText"
    :confirm-variant="variant"
    @close="$emit('cancel')"
    @confirm="$emit('confirm')"
  >
    <div class="flex items-start space-x-4">
      <div
        class="flex-shrink-0 w-12 h-12 rounded-full flex items-center justify-center"
        :class="iconBackgroundClass"
      >
        <svg class="w-6 h-6" :class="iconColorClass" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path
            v-if="variant === 'danger'"
            stroke-linecap="round"
            stroke-linejoin="round"
            stroke-width="2"
            d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
          />
          <path
            v-else-if="variant === 'success'"
            stroke-linecap="round"
            stroke-linejoin="round"
            stroke-width="2"
            d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"
          />
          <path
            v-else
            stroke-linecap="round"
            stroke-linejoin="round"
            stroke-width="2"
            d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
          />
        </svg>
      </div>
      <div class="flex-1">
        <p class="text-sm text-gray-600 leading-relaxed">
          {{ message }}
        </p>
      </div>
    </div>
  </BaseModal>
</template>

<script setup>
import { computed } from 'vue';
import BaseModal from './BaseModal.vue';

const props = defineProps({
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
  variant: {
    type: String,
    default: 'danger',
    validator: (value) => ['primary', 'danger', 'success'].includes(value),
  },
});

defineEmits(['confirm', 'cancel']);

const iconBackgroundClass = computed(() => {
  const classes = {
    primary: 'bg-blue-100',
    danger: 'bg-red-100',
    success: 'bg-green-100',
  };
  return classes[props.variant];
});

const iconColorClass = computed(() => {
  const classes = {
    primary: 'text-blue-600',
    danger: 'text-red-600',
    success: 'text-green-600',
  };
  return classes[props.variant];
});
</script>
