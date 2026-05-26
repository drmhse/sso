<template>
  <button
    :type="type"
    :disabled="disabled || loading"
    class="btn"
    :class="variantClass"
    @click="$emit('click', $event)"
  >
    <span v-if="loading" class="spinner" style="width: 16px; height: 16px; border-width: 2px; margin-right: 8px;"></span>
    <slot />
  </button>
</template>

<script setup>
import { computed } from 'vue';

const props = defineProps({
  type: { type: String, default: 'button' },
  variant: { type: String, default: 'primary' },
  disabled: { type: Boolean, default: false },
  loading: { type: Boolean, default: false },
});

defineEmits(['click']);

const variantClass = computed(() => ({
  'btn-primary': props.variant === 'primary',
  'btn-secondary': props.variant === 'secondary',
  'btn-danger': props.variant === 'danger',
}));
</script>
