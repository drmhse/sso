<template>
  <div class="w-full">
    <label
      v-if="label"
      :for="id"
      class="block text-sm font-medium text-gray-700 mb-1"
    >
      {{ label }}
      <span v-if="required" class="text-red-500">*</span>
    </label>

    <div class="relative">
      <input
        :id="id"
        :type="type"
        :value="modelValue"
        :placeholder="placeholder"
        :required="required"
        :disabled="disabled"
        :readonly="readonly"
        :autocomplete="autocomplete"
        :class="inputClasses"
        @input="$emit('update:modelValue', $event.target.value)"
        @blur="$emit('blur', $event)"
        @focus="$emit('focus', $event)"
      />

      <div
        v-if="error"
        class="absolute inset-y-0 right-0 pr-3 flex items-center pointer-events-none"
      >
        <svg
          class="h-5 w-5 text-red-500"
          fill="currentColor"
          viewBox="0 0 20 20"
        >
          <path
            fill-rule="evenodd"
            d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z"
            clip-rule="evenodd"
          />
        </svg>
      </div>
    </div>

    <p v-if="error" class="mt-1 text-sm text-red-600">
      {{ error }}
    </p>

    <p v-else-if="hint" class="mt-1 text-sm text-gray-500">
      {{ hint }}
    </p>
  </div>
</template>

<script setup>
import { computed } from 'vue';

const props = defineProps({
  id: {
    type: String,
    default: () => `input-${Math.random().toString(36).substr(2, 9)}`,
  },
  modelValue: {
    type: [String, Number],
    default: '',
  },
  label: {
    type: String,
    default: '',
  },
  type: {
    type: String,
    default: 'text',
  },
  placeholder: {
    type: String,
    default: '',
  },
  hint: {
    type: String,
    default: '',
  },
  error: {
    type: String,
    default: '',
  },
  required: {
    type: Boolean,
    default: false,
  },
  disabled: {
    type: Boolean,
    default: false,
  },
  readonly: {
    type: Boolean,
    default: false,
  },
  autocomplete: {
    type: String,
    default: 'off',
  },
});

defineEmits(['update:modelValue', 'blur', 'focus']);

const inputClasses = computed(() => {
  const base = [
    'block',
    'w-full',
    'rounded-md',
    'shadow-sm',
    'sm:text-sm',
    'focus:outline-none',
    'focus:ring-2',
    'focus:ring-offset-0',
    'transition-colors',
  ];

  const state = props.error
    ? [
        'border-red-300',
        'text-red-900',
        'placeholder-red-300',
        'focus:ring-red-500',
        'focus:border-red-500',
      ]
    : [
        'border-gray-300',
        'focus:ring-blue-500',
        'focus:border-blue-500',
      ];

  const disabled = props.disabled
    ? ['bg-gray-100', 'cursor-not-allowed']
    : [];

  return [...base, ...state, ...disabled];
});
</script>
