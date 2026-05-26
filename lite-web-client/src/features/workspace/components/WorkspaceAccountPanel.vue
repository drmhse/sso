<template>
  <section id="account" class="panel stack">
    <div>
      <h2>Account</h2>
      <p class="muted">Update your account email and password.</p>
    </div>

    <div v-if="message" class="alert" :class="messageType === 'success' ? 'alert-success' : 'alert-error'">
      {{ message }}
    </div>

    <div class="field">
      <label for="account-email">Email address</label>
      <input id="account-email" v-model="accountEmail" type="email" class="input" />
    </div>
    <BaseButton :loading="accountSaving" @click="saveAccount">Save account details</BaseButton>

    <div class="field">
      <label for="current-password">Current password</label>
      <input id="current-password" v-model="passwordForm.current" type="password" class="input" />
    </div>
    <div class="field">
      <label for="new-password">New password</label>
      <input id="new-password" v-model="passwordForm.next" type="password" class="input" />
    </div>
    <BaseButton :loading="passwordSaving" @click="changePassword">Change password</BaseButton>
  </section>
</template>

<script setup>
import { ref, watch } from 'vue';
import { sso } from '@/lib/api';
import BaseButton from '@/components/BaseButton.vue';
import { useAuthStore } from '@/stores/auth';

const props = defineProps({
  refreshKey: { type: Number, default: 0 },
});

const authStore = useAuthStore();

const accountEmail = ref('');
const accountSaving = ref(false);
const passwordSaving = ref(false);
const message = ref('');
const messageType = ref('success');
const passwordForm = ref({ current: '', next: '' });

watch(
  () => [props.refreshKey, authStore.user?.email],
  () => {
    accountEmail.value = authStore.user?.email || '';
  },
  { immediate: true },
);

async function saveAccount() {
  accountSaving.value = true;
  message.value = '';

  try {
    await sso.user.updateProfile({ email: accountEmail.value });
    await authStore.refreshUser();
    messageType.value = 'success';
    message.value = 'Account email updated.';
  } catch (error) {
    messageType.value = 'error';
    message.value = error.message || 'Failed to update the account email.';
  } finally {
    accountSaving.value = false;
  }
}

async function changePassword() {
  if (passwordForm.value.next.length < 8) {
    messageType.value = 'error';
    message.value = 'Use a new password with at least 8 characters.';
    return;
  }

  passwordSaving.value = true;
  message.value = '';

  try {
    await sso.user.changePassword({
      current_password: passwordForm.value.current,
      new_password: passwordForm.value.next,
    });
    passwordForm.value = { current: '', next: '' };
    messageType.value = 'success';
    message.value = 'Password changed.';
  } catch (error) {
    messageType.value = 'error';
    message.value = error.message || 'Failed to change password.';
  } finally {
    passwordSaving.value = false;
  }
}
</script>
