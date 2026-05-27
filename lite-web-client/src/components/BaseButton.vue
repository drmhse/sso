<template>
  <button
    :type="type"
    :disabled="disabled || loading"
    class="btn"
    :class="[variantClass, sizeClass, { 'btn-block': block, 'btn-loading': loading }]"
    @click="$emit('click', $event)"
  >
    <span v-if="loading" class="spinner spinner-inline"></span>
    <span v-else-if="$slots.icon" class="btn-icon">
      <slot name="icon" />
    </span>
    <span class="btn-label">
      <slot />
    </span>
    <span v-if="$slots.trailing" class="btn-icon">
      <slot name="trailing" />
    </span>
  </button>
</template>

<script setup>
import { computed } from 'vue';

const props = defineProps({
  type: { type: String, default: 'button' },
  variant: { type: String, default: 'primary' },
  size: { type: String, default: 'md' },
  disabled: { type: Boolean, default: false },
  loading: { type: Boolean, default: false },
  block: { type: Boolean, default: false },
});

defineEmits(['click']);

const variantClass = computed(() => ({
  'btn-primary': props.variant === 'primary',
  'btn-secondary': props.variant === 'secondary',
  'btn-danger': props.variant === 'danger',
  'btn-ghost': props.variant === 'ghost',
}));

const sizeClass = computed(() => ({
  'btn-sm': props.size === 'sm',
  'btn-lg': props.size === 'lg',
}));
</script>
