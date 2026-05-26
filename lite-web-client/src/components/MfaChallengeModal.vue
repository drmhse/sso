<template>
  <div v-if="isOpen" class="overlay">
    <div class="dialog stack">
      <div>
        <h2 style="margin: 0;">Two-factor authentication</h2>
        <p class="muted" style="margin: 8px 0 0;">
          Enter the code from your authenticator app or use a backup code.
        </p>
      </div>

      <div v-if="error" class="alert alert-error">{{ error }}</div>

      <div class="field">
        <label for="mfa-code">Authenticator code</label>
        <input
          id="mfa-code"
          v-model="code"
          class="input code"
          inputmode="numeric"
          maxlength="6"
          placeholder="000000"
          @keyup.enter="handleVerify"
        />
      </div>

      <button class="btn btn-secondary" @click="showBackup = !showBackup">
        {{ showBackup ? 'Use authenticator code instead' : 'Use a backup code instead' }}
      </button>

      <div v-if="showBackup" class="field">
        <label for="backup-code">Backup code</label>
        <input
          id="backup-code"
          v-model="backupCode"
          class="input code"
          maxlength="9"
          placeholder="ABCD-1234"
          @input="normalizeBackup"
          @keyup.enter="handleVerify"
        />
      </div>

      <div class="button-row" style="justify-content: flex-end;">
        <BaseButton variant="secondary" @click="$emit('close')">Cancel</BaseButton>
        <BaseButton variant="secondary" @click="$emit('lost-device')">Need help</BaseButton>
        <BaseButton :loading="verifying" @click="handleVerify">Verify</BaseButton>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, watch } from 'vue';
import BaseButton from './BaseButton.vue';

const props = defineProps({
  isOpen: { type: Boolean, required: true },
  preauthToken: { type: String, default: '' },
  deviceCodeId: { type: String, default: null },
});

const emit = defineEmits(['close', 'success', 'lost-device']);

const code = ref('');
const backupCode = ref('');
const showBackup = ref(false);
const verifying = ref(false);
const error = ref('');

watch(() => props.isOpen, (open) => {
  if (open) {
    code.value = '';
    backupCode.value = '';
    showBackup.value = false;
    verifying.value = false;
    error.value = '';
  }
});

function normalizeBackup() {
  let next = backupCode.value.toUpperCase().replace(/[^A-Z0-9]/g, '');
  if (next.length > 4) next = `${next.slice(0, 4)}-${next.slice(4, 8)}`;
  backupCode.value = next;
  error.value = '';
}

function handleVerify() {
  const payload = showBackup.value ? backupCode.value.replace('-', '') : code.value.replace(/\D/g, '');
  if (!props.preauthToken || payload.length < 6) {
    error.value = 'Enter a valid verification code.';
    return;
  }

  verifying.value = true;
  emit('success', {
    code: payload,
    deviceCodeId: props.deviceCodeId,
  });
}
</script>
