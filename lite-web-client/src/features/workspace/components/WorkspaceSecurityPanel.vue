<template>
  <section id="security" class="panel stack">
    <div>
      <h2>Security</h2>
      <p class="muted">Manage MFA, passkeys, and trusted devices.</p>
    </div>

    <div v-if="message" class="alert" :class="messageType === 'success' ? 'alert-success' : 'alert-error'">
      {{ message }}
    </div>

    <div class="meta-grid">
      <div class="meta-item">
        <div class="meta-label">MFA</div>
        <div class="meta-value">{{ mfaStatus?.enabled ? 'Enabled' : 'Disabled' }}</div>
      </div>
      <div class="meta-item">
        <div class="meta-label">Backup codes</div>
        <div class="meta-value">{{ mfaStatus?.has_backup_codes ? 'Available' : 'Missing' }}</div>
      </div>
      <div class="meta-item">
        <div class="meta-label">Passkeys</div>
        <div class="meta-value">{{ passkeys.length }}</div>
      </div>
      <div class="meta-item">
        <div class="meta-label">Trusted devices</div>
        <div class="meta-value">{{ devices.length }}</div>
      </div>
    </div>

    <div class="button-row">
      <BaseButton variant="secondary" @click="startMfaSetup" v-if="!mfaStatus?.enabled">Enable MFA</BaseButton>
      <BaseButton variant="danger" @click="disableMfa" v-else>Disable MFA</BaseButton>
      <BaseButton variant="secondary" @click="regenerateBackupCodes" v-if="mfaStatus?.enabled">Regenerate backup codes</BaseButton>
      <BaseButton variant="secondary" @click="registerPasskey">Register passkey</BaseButton>
    </div>

    <div v-if="mfaSetup" class="stack">
      <div class="alert alert-warning">Scan the QR code and enter a six-digit code to finish MFA setup.</div>
      <div class="panel qr-shell">
        <div v-html="mfaSetup.qr_code_svg"></div>
      </div>
      <div class="field">
        <label for="mfa-setup-code">Verification code</label>
        <input id="mfa-setup-code" v-model="mfaCode" class="input code" maxlength="6" />
      </div>
      <BaseButton @click="completeMfaSetup">Complete MFA setup</BaseButton>
    </div>

    <div v-if="backupCodes.length" class="stack">
      <div class="alert alert-success">Save these backup codes now. They are only shown once.</div>
      <div class="meta-grid">
        <div v-for="code in backupCodes" :key="code" class="meta-item code">{{ code }}</div>
      </div>
    </div>

    <div class="stack">
      <h3>Passkeys</h3>
      <div v-if="passkeys.length === 0" class="muted">No passkeys are registered.</div>
      <div v-else class="list">
        <div v-for="passkey in passkeys" :key="passkey.id" class="list-item">
          <div>
            <div>{{ passkey.name }}</div>
            <div class="muted">{{ passkey.created_at }}</div>
          </div>
          <div class="button-row">
            <BaseButton variant="secondary" @click="renamePasskey(passkey)">Rename</BaseButton>
            <BaseButton variant="danger" @click="deletePasskey(passkey.id)">Delete</BaseButton>
          </div>
        </div>
      </div>
    </div>

    <div class="stack">
      <h3>Trusted devices</h3>
      <div v-if="devices.length === 0" class="muted">No trusted devices are registered.</div>
      <div v-else class="list">
        <div v-for="device in devices" :key="device.id" class="list-item">
          <div>
            <div>{{ device.device_name }}</div>
            <div class="muted">Last used {{ formatDate(device.last_used_at) }} · Risk {{ device.risk_score }}</div>
          </div>
          <div class="button-row">
            <BaseButton variant="secondary" @click="renameDevice(device)">Rename</BaseButton>
            <BaseButton variant="danger" @click="revokeDevice(device.id)">Revoke</BaseButton>
          </div>
        </div>
      </div>
    </div>
  </section>
</template>

<script setup>
import { ref, watch } from 'vue';
import { sso } from '@/lib/api';
import BaseButton from '@/components/BaseButton.vue';
import { useWorkspaceStore } from '@/stores/workspace';

const props = defineProps({
  refreshKey: { type: Number, default: 0 },
});

const workspaceStore = useWorkspaceStore();

const message = ref('');
const messageType = ref('success');
const mfaStatus = ref(null);
const mfaSetup = ref(null);
const mfaCode = ref('');
const backupCodes = ref([]);
const passkeys = ref([]);
const devices = ref([]);

watch(
  () => props.refreshKey,
  async () => {
    if (workspaceStore.mode === 'ready') {
      await Promise.all([loadMfaStatus(), loadPasskeys(), loadDevices()]);
    } else {
      mfaStatus.value = null;
      mfaSetup.value = null;
      mfaCode.value = '';
      backupCodes.value = [];
      passkeys.value = [];
      devices.value = [];
    }
  },
  { immediate: true },
);

async function loadMfaStatus() {
  mfaStatus.value = await sso.user.mfa.getStatus();
}

async function startMfaSetup() {
  message.value = '';
  try {
    mfaSetup.value = await sso.user.mfa.setup();
  } catch (error) {
    messageType.value = 'error';
    message.value = error.message || 'Failed to start MFA setup.';
  }
}

async function completeMfaSetup() {
  try {
    const response = await sso.user.mfa.verify(mfaCode.value);
    mfaSetup.value = null;
    mfaCode.value = '';
    backupCodes.value = response.backup_codes || [];
    messageType.value = 'success';
    message.value = 'MFA enabled.';
    await loadMfaStatus();
  } catch (error) {
    messageType.value = 'error';
    message.value = error.message || 'Failed to finish MFA setup.';
  }
}

async function disableMfa() {
  if (!window.confirm('Disable MFA for this account?')) return;
  try {
    await sso.user.mfa.disable();
    backupCodes.value = [];
    messageType.value = 'success';
    message.value = 'MFA disabled.';
    await loadMfaStatus();
  } catch (error) {
    messageType.value = 'error';
    message.value = error.message || 'Failed to disable MFA.';
  }
}

async function regenerateBackupCodes() {
  if (!window.confirm('Generate new backup codes and invalidate the old set?')) return;
  try {
    const response = await sso.user.mfa.regenerateBackupCodes();
    backupCodes.value = response.backup_codes || [];
    messageType.value = 'success';
    message.value = 'Backup codes regenerated.';
  } catch (error) {
    messageType.value = 'error';
    message.value = error.message || 'Failed to regenerate backup codes.';
  }
}

async function loadPasskeys() {
  passkeys.value = await sso.passkeys.list();
}

async function registerPasskey() {
  const name = window.prompt('Name this passkey', 'Current device');
  if (name === null) return;

  try {
    await sso.passkeys.register(name || undefined);
    messageType.value = 'success';
    message.value = 'Passkey registered.';
    await loadPasskeys();
  } catch (error) {
    messageType.value = 'error';
    message.value = error.message || 'Failed to register a passkey.';
  }
}

async function renamePasskey(passkey) {
  const name = window.prompt('Rename passkey', passkey.name);
  if (!name) return;

  try {
    await sso.passkeys.updateName(passkey.id, name);
    await loadPasskeys();
  } catch (error) {
    messageType.value = 'error';
    message.value = error.message || 'Failed to rename the passkey.';
  }
}

async function deletePasskey(passkeyId) {
  if (!window.confirm('Delete this passkey?')) return;

  try {
    await sso.passkeys.delete(passkeyId);
    await loadPasskeys();
  } catch (error) {
    messageType.value = 'error';
    message.value = error.message || 'Failed to delete the passkey.';
  }
}

async function loadDevices() {
  const response = await sso.user.devices.list();
  devices.value = response.devices || [];
}

async function renameDevice(device) {
  const name = window.prompt('Rename device', device.device_name);
  if (!name) return;

  try {
    await sso.user.devices.updateName(device.id, name);
    await loadDevices();
  } catch (error) {
    messageType.value = 'error';
    message.value = error.message || 'Failed to rename the device.';
  }
}

async function revokeDevice(deviceId) {
  if (!window.confirm('Revoke this device?')) return;

  try {
    await sso.user.devices.revoke(deviceId);
    await loadDevices();
  } catch (error) {
    messageType.value = 'error';
    message.value = error.message || 'Failed to revoke the device.';
  }
}

function formatDate(value) {
  if (!value) return 'never';
  return new Date(value).toLocaleString();
}
</script>
