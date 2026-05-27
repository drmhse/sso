<template>
  <section class="workspace-card stack">
    <div class="section-header">
      <div>
        <h2 class="section-title">Account Profile</h2>
        <p class="section-copy">Update the active account email and rotate the password from one place.</p>
      </div>
    </div>

    <div class="field">
      <label for="account-email">Email address</label>
      <input
        id="account-email"
        :value="accountEmail"
        type="email"
        class="input"
        @input="$emit('update:accountEmail', $event.target.value)"
      />
    </div>

    <BaseButton :loading="accountSaving" @click="$emit('save-account')">
      Save account details
    </BaseButton>

    <div class="field">
      <label for="current-password">Current password</label>
      <input
        id="current-password"
        :value="passwordForm.current"
        type="password"
        class="input"
        @input="$emit('update:passwordForm', { ...passwordForm, current: $event.target.value })"
      />
    </div>

    <div class="field">
      <label for="new-password">New password</label>
      <input
        id="new-password"
        :value="passwordForm.next"
        type="password"
        class="input"
        placeholder="Minimum 8 characters"
        @input="$emit('update:passwordForm', { ...passwordForm, next: $event.target.value })"
      />
    </div>

    <BaseButton :loading="passwordSaving" @click="$emit('change-password')">
      Change password
    </BaseButton>
  </section>
</template>

<script setup>
import BaseButton from '@/components/BaseButton.vue';

defineProps({
  accountEmail: { type: String, default: '' },
  passwordForm: {
    type: Object,
    default: () => ({ current: '', next: '' }),
  },
  accountSaving: { type: Boolean, default: false },
  passwordSaving: { type: Boolean, default: false },
});

defineEmits(['update:accountEmail', 'update:passwordForm', 'save-account', 'change-password']);
</script>
