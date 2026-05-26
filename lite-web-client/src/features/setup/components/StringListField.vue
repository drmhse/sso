<template>
  <div class="field">
    <label :for="inputId">{{ label }}</label>
    <textarea
      :id="inputId"
      v-model="textValue"
      class="textarea code"
      :placeholder="placeholder"
      spellcheck="false"
    />
    <div v-if="hint" class="muted">{{ hint }}</div>
  </div>
</template>

<script setup>
import { computed } from 'vue';

const props = defineProps({
  id: { type: String, required: true },
  label: { type: String, required: true },
  modelValue: {
    type: Array,
    default: () => [],
  },
  placeholder: { type: String, default: '' },
  hint: { type: String, default: '' },
});

const emit = defineEmits(['update:modelValue']);

const inputId = computed(() => props.id);
const textValue = computed({
  get: () => (props.modelValue || []).join('\n'),
  set: (value) => {
    emit(
      'update:modelValue',
      value
        .split('\n')
        .map((item) => item.trim())
        .filter(Boolean),
    );
  },
});
</script>
