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
      <div class="backup-code-toolbar">
        <div class="alert alert-success">Save these backup codes now. They are only shown once.</div>
        <div class="button-row backup-code-actions">
          <BaseButton variant="secondary" size="sm" @click="copyBackupCodes">
            <template #icon>
              <Copy class="btn-icon-svg" />
            </template>
            {{ copied ? 'Copied' : 'Copy Codes' }}
          </BaseButton>
          <BaseButton variant="secondary" size="sm" @click="downloadBackupCodes">
            <template #icon>
              <Download class="btn-icon-svg" />
            </template>
            Download .txt
          </BaseButton>
        </div>
      </div>
      <div class="backup-code-grid">
        <div v-for="code in backupCodes" :key="code" class="backup-code-tile code">{{ code }}</div>
      </div>
    </div>
  </section>
</template>

<script setup>
import { computed, ref } from 'vue';
import { Copy, Download } from '@lucide/vue';
import BaseButton from '@/components/BaseButton.vue';

const props = defineProps({
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

const copied = ref(false);

const backupCodesText = computed(() => [
  'AuthOS backup codes',
  `Generated: ${new Date().toISOString()}`,
  '',
  'Store these codes somewhere safe. Each code can be used once if you cannot access your authenticator app.',
  '',
  ...props.backupCodes,
  '',
].join('\n'));

async function copyBackupCodes() {
  await writeTextToClipboard(backupCodesText.value);
  copied.value = true;
  window.setTimeout(() => {
    copied.value = false;
  }, 2200);
}

async function writeTextToClipboard(text) {
  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(text);
      return;
    } catch {
      // Fall back for browsers that block async clipboard outside secure contexts.
    }
  }

  const textarea = document.createElement('textarea');
  textarea.value = text;
  textarea.setAttribute('readonly', '');
  textarea.style.position = 'fixed';
  textarea.style.top = '-9999px';
  document.body.appendChild(textarea);
  textarea.select();
  document.execCommand('copy');
  textarea.remove();
}

function downloadBackupCodes() {
  const blob = new Blob([backupCodesText.value], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `authos-backup-codes-${new Date().toISOString().slice(0, 10)}.txt`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}
</script>
