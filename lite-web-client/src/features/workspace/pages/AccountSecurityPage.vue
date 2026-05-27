<template>
  <div class="workspace-page stack-lg">
    <div v-if="message" class="alert" :class="messageType === 'success' ? 'alert-success' : 'alert-error'">
      {{ message }}
    </div>

    <section v-if="workspaceStore.mode === 'loading'" class="workspace-card">
      <LoadingSpinner text="Loading account security..." />
    </section>
    <section v-else-if="workspaceStore.mode !== 'ready'" class="workspace-card stack">
      <h2 class="section-title">Account security is not available</h2>
      <p class="section-copy">
        AuthOS Lite can only manage account security after a single active organization has been resolved.
      </p>
    </section>
    <template v-else>
      <AccountProfileCard
        :account-email="accountEmail"
        :password-form="passwordForm"
        :account-saving="accountSaving"
        :password-saving="passwordSaving"
        @update:account-email="accountEmail = $event"
        @update:password-form="passwordForm = $event"
        @save-account="saveAccount"
        @change-password="changePassword"
      />

      <SecurityMfaCard
        :mfa-status="mfaStatus"
        :mfa-setup="mfaSetup"
        :mfa-code="mfaCode"
        :backup-codes="backupCodes"
        @update:mfa-code="mfaCode = $event"
        @start-setup="startMfaSetup"
        @complete-setup="completeMfaSetup"
        @disable="openDisableMfaDialog"
        @regenerate-backups="openRegenerateBackupDialog"
      />

      <SecurityPasskeysCard
        :passkeys="passkeys"
        @register="openRegisterPasskeyDialog"
        @rename="openRenamePasskeyDialog"
        @delete="openDeletePasskeyDialog"
      />

      <SecurityDevicesCard
        :devices="devices"
        @rename="openRenameDeviceDialog"
        @revoke="openRevokeDeviceDialog"
      />
    </template>

    <BaseDialog
      :open="dialog.open"
      :title="dialog.title"
      :description="dialog.description"
      :close-label="'Cancel'"
      @close="closeDialog"
    >
      <div v-if="dialog.inputLabel" class="field">
        <label for="security-dialog-input">{{ dialog.inputLabel }}</label>
        <input
          id="security-dialog-input"
          v-model="dialog.inputValue"
          class="input"
          type="text"
        />
      </div>

      <template #actions>
        <BaseButton
          :variant="dialogConfirmVariant"
          :loading="dialogBusy"
          :disabled="Boolean(dialog.inputLabel) && !dialog.inputValue.trim()"
          @click="confirmDialog"
        >
          {{ dialog.confirmLabel }}
        </BaseButton>
      </template>
    </BaseDialog>
  </div>
</template>

<script setup>
import { ref, watch } from 'vue';
import BaseDialog from '@/components/BaseDialog.vue';
import BaseButton from '@/components/BaseButton.vue';
import LoadingSpinner from '@/components/LoadingSpinner.vue';
import AccountProfileCard from '@/features/workspace/components/security/AccountProfileCard.vue';
import SecurityDevicesCard from '@/features/workspace/components/security/SecurityDevicesCard.vue';
import SecurityMfaCard from '@/features/workspace/components/security/SecurityMfaCard.vue';
import SecurityPasskeysCard from '@/features/workspace/components/security/SecurityPasskeysCard.vue';
import { useSecurityCenter } from '@/features/workspace/useSecurityCenter';
import { useWorkspaceRuntime } from '@/features/workspace/useWorkspaceRuntime';
import { sso } from '@/lib/api';
import { useAuthStore } from '@/stores/auth';
import { useWorkspaceStore } from '@/stores/workspace';

const authStore = useAuthStore();
const workspaceStore = useWorkspaceStore();
const { refreshVersion } = useWorkspaceRuntime();

const accountEmail = ref('');
const accountSaving = ref(false);
const passwordSaving = ref(false);
const passwordForm = ref({ current: '', next: '' });

const {
  message,
  messageType,
  mfaStatus,
  mfaSetup,
  mfaCode,
  backupCodes,
  passkeys,
  devices,
  dialog,
  dialogBusy,
  dialogConfirmVariant,
  startMfaSetup,
  completeMfaSetup,
  openDisableMfaDialog,
  openRegenerateBackupDialog,
  openRegisterPasskeyDialog,
  openRenamePasskeyDialog,
  openDeletePasskeyDialog,
  openRenameDeviceDialog,
  openRevokeDeviceDialog,
  confirmDialog,
  closeDialog,
  setSuccess,
  setError,
} = useSecurityCenter(refreshVersion);

watch(
  () => [refreshVersion.value, authStore.user?.email],
  () => {
    accountEmail.value = authStore.user?.email || '';
  },
  { immediate: true },
);

async function saveAccount() {
  accountSaving.value = true;

  try {
    await sso.user.updateProfile({ email: accountEmail.value });
    await authStore.refreshUser();
    setSuccess('Account email updated.');
  } catch (error) {
    setError(error.message || 'Failed to update the account email.');
  } finally {
    accountSaving.value = false;
  }
}

async function changePassword() {
  if (passwordForm.value.next.length < 8) {
    setError('Use a new password with at least 8 characters.');
    return;
  }

  passwordSaving.value = true;

  try {
    await sso.user.changePassword({
      current_password: passwordForm.value.current,
      new_password: passwordForm.value.next,
    });
    passwordForm.value = { current: '', next: '' };
    setSuccess('Password changed.');
  } catch (error) {
    setError(error.message || 'Failed to change password.');
  } finally {
    passwordSaving.value = false;
  }
}
</script>
