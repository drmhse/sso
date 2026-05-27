<template>
  <div class="stack">
    <div class="auth-step-meta">
      <div>
        <div class="auth-step-meta__label">Email</div>
        <div class="auth-step-meta__value">{{ email }}</div>
      </div>
      <button type="button" class="text-link text-link--strong" @click="$emit('change-email')">
        Edit
      </button>
    </div>

    <div v-if="upstreamProvider" class="stack">
      <div class="alert alert-warning">
        This account is managed by {{ upstreamProvider }}.
      </div>
      <BaseButton block @click="$emit('oauth', 'oidc', connectionId)">
        Continue with {{ upstreamProvider }}
      </BaseButton>
    </div>

    <template v-else>
      <div class="field">
        <label for="login-password">Password</label>
        <input
          id="login-password"
          :value="password"
          class="input input-lg"
          type="password"
          placeholder="Enter your password"
          autocomplete="current-password"
          @input="$emit('update:password', $event.target.value)"
          @keyup.enter="$emit('submit')"
        />
      </div>

      <BaseButton :loading="loading" block @click="$emit('submit')">
        Sign In
      </BaseButton>

      <div class="auth-inline-links">
        <button v-if="canUseMagicLink" type="button" class="text-link" @click="$emit('magic-link')">
          Send a magic link instead
        </button>
        <router-link :to="forgotPasswordTo" class="text-link">Forgot password?</router-link>
      </div>

      <div v-if="canUsePasskey" class="stack">
        <p class="auth-divider"><span>Or continue with</span></p>
        <BaseButton variant="secondary" :loading="passkeyLoading" block @click="$emit('passkey')">
          <template #icon>
            <KeyRound class="btn-icon-svg" />
          </template>
          Passkey
        </BaseButton>
      </div>
    </template>
  </div>
</template>

<script setup>
import { KeyRound } from '@lucide/vue';
import BaseButton from '@/components/BaseButton.vue';

defineProps({
  email: { type: String, default: '' },
  password: { type: String, default: '' },
  canUseMagicLink: { type: Boolean, default: false },
  canUsePasskey: { type: Boolean, default: false },
  magicLinkLoading: { type: Boolean, default: false },
  passkeyLoading: { type: Boolean, default: false },
  loading: { type: Boolean, default: false },
  upstreamProvider: { type: String, default: '' },
  connectionId: { type: String, default: '' },
  forgotPasswordTo: { type: String, default: '/forgot-password' },
});

defineEmits([
  'update:password',
  'oauth',
  'magic-link',
  'passkey',
  'submit',
  'change-email',
]);
</script>
