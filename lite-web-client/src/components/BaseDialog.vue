<template>
  <Teleport to="body">
    <div v-if="open" class="overlay" @click.self="handleClose">
      <section class="dialog" role="dialog" :aria-labelledby="titleId" aria-modal="true">
        <header class="dialog__header">
          <div>
            <h2 :id="titleId" class="dialog__title">{{ title }}</h2>
            <p v-if="description" class="dialog__description">{{ description }}</p>
          </div>

          <button
            v-if="showClose"
            type="button"
            class="dialog__close"
            aria-label="Close dialog"
            @click="handleClose"
          >
            ×
          </button>
        </header>

        <div class="dialog__body">
          <slot />
        </div>

        <footer v-if="$slots.actions || !hideDefaultActions" class="dialog__actions">
          <BaseButton v-if="!hideDefaultActions" variant="secondary" @click="handleClose">
            {{ closeLabel }}
          </BaseButton>
          <slot name="actions" />
        </footer>
      </section>
    </div>
  </Teleport>
</template>

<script setup>
import { computed } from 'vue';
import BaseButton from '@/components/BaseButton.vue';

const props = defineProps({
  open: { type: Boolean, default: false },
  title: { type: String, default: '' },
  description: { type: String, default: '' },
  closeLabel: { type: String, default: 'Cancel' },
  hideDefaultActions: { type: Boolean, default: false },
  showClose: { type: Boolean, default: true },
});

const emit = defineEmits(['close']);

const titleId = computed(() => `dialog-${Math.random().toString(36).slice(2, 9)}`);

function handleClose() {
  emit('close');
}
</script>
