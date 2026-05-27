<template>
  <div class="stack">
    <div class="field">
      <label for="login-email">Email address</label>
      <input
        id="login-email"
        :value="modelValue"
        class="input input-lg"
        type="email"
        placeholder="name@example.com"
        autocomplete="email"
        @input="$emit('update:modelValue', $event.target.value)"
        @keyup.enter="$emit('continue')"
      />
    </div>

    <BaseButton :loading="loading" block @click="$emit('continue')">
      Continue
    </BaseButton>

    <template v-if="providers.length">
      <p class="auth-divider"><span>Or continue with</span></p>

      <div class="auth-provider-grid">
        <BaseButton
          v-for="provider in providers"
          :key="provider.key"
          variant="secondary"
          block
          @click="$emit('oauth', provider.key)"
        >
          <template #icon>
            <component :is="provider.icon" class="btn-icon-svg" />
          </template>
          {{ provider.label }}
        </BaseButton>
      </div>
    </template>
  </div>
</template>

<script setup>
import BaseButton from '@/components/BaseButton.vue';

defineProps({
  modelValue: { type: String, default: '' },
  providers: { type: Array, default: () => [] },
  loading: { type: Boolean, default: false },
});

defineEmits(['update:modelValue', 'continue', 'oauth']);
</script>
