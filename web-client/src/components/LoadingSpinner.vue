<template>
  <div class="flex items-center justify-center" :class="containerClass">
    <div
      class="animate-spin rounded-full border-b-2"
      :class="spinnerClass"
    ></div>
    <span v-if="text" class="ml-3 text-gray-600" :class="textClass">
      {{ text }}
    </span>
  </div>
</template>

<script setup>
import { computed } from 'vue';

const props = defineProps({
  size: {
    type: String,
    default: 'md',
    validator: (value) => ['sm', 'md', 'lg', 'xl'].includes(value),
  },
  text: {
    type: String,
    default: '',
  },
  fullScreen: {
    type: Boolean,
    default: false,
  },
});

const spinnerClass = computed(() => {
  const sizes = {
    sm: 'h-4 w-4',
    md: 'h-8 w-8',
    lg: 'h-12 w-12',
    xl: 'h-16 w-16',
  };
  return `${sizes[props.size]} border-blue-600`;
});

const textClass = computed(() => {
  const sizes = {
    sm: 'text-xs',
    md: 'text-sm',
    lg: 'text-base',
    xl: 'text-lg',
  };
  return sizes[props.size];
});

const containerClass = computed(() => {
  return props.fullScreen ? 'min-h-screen' : 'p-4';
});
</script>
