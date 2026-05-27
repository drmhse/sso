<template>
  <section class="workspace-card stack">
    <div class="section-header">
      <div>
        <h2 class="section-title">Multi-Factor Authentication (MFA)</h2>
        <p class="section-copy">Protect this operator account with an authenticator app and one-time backup codes.</p>
      </div>
      <span class="status-chip" :class="mfaStatus?.enabled ? 'status-chip--success' : 'status-chip--neutral'">
        {{ mfaStatus?.enabled ? 'Enabled' : 'Disabled' }}
      </span>
    </div>

    <div class="detail-list">
      <div class="detail-list__row">
        <span class="detail-list__label">Backup codes</span>
        <strong class="detail-list__value">{{ mfaStatus?.has_backup_codes ? 'Available' : 'Missing' }}</strong>
      </div>
    </div>

    <div class="button-row">
      <BaseButton v-if="!mfaStatus?.enabled" variant="secondary" @click="$emit('start-setup')">
        Enable MFA
      </BaseButton>
      <template v-else>
        <BaseButton variant="secondary" @click="$emit('regenerate-backups')">
          Regenerate Backup Codes
        </BaseButton>
        <BaseButton variant="danger" @click="$emit('disable')">
          Disable MFA
        </BaseButton>
      </template>
    </div>

    <div v-if="mfaSetup" class="stack">
      <div class="panel-subtle">
        <div class="qr-shell" v-html="mfaSetup.qr_code_svg"></div>
      </div>

      <div class="field">
        <label for="mfa-setup-code">Authenticator code</label>
        <input
          id="mfa-setup-code"
          :value="mfaCode"
          class="input code"
          maxlength="6"
          placeholder="000000"
          @input="$emit('update:mfaCode', $event.target.value)"
        />
      </div>

      <BaseButton @click="$emit('complete-setup')">
        Complete MFA Setup
      </BaseButton>
    </div>

    <div v-if="backupCodes.length" class="stack">
      <div class="alert alert-success">Save these backup codes now. They are only shown once.</div>
      <div class="backup-code-grid">
        <div v-for="code in backupCodes" :key="code" class="backup-code-tile code">{{ code }}</div>
      </div>
    </div>
  </section>
</template>

<script setup>
import BaseButton from '@/components/BaseButton.vue';

defineProps({
  mfaStatus: { type: Object, default: null },
  mfaSetup: { type: Object, default: null },
  mfaCode: { type: String, default: '' },
  backupCodes: { type: Array, default: () => [] },
});

defineEmits([
  'start-setup',
  'complete-setup',
  'disable',
  'regenerate-backups',
  'update:mfaCode',
]);
</script>
