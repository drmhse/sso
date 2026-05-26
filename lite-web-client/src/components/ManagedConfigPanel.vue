<template>
  <section class="panel stack">
    <div>
      <h2>Setup</h2>
      <p class="muted">
        Manage the installed AuthOS configuration through structured fields, then reload the service from the lite admin workspace.
      </p>
    </div>

    <div v-if="message" class="alert" :class="messageType === 'success' ? 'alert-success' : 'alert-error'">
      {{ message }}
    </div>

    <LoadingSpinner v-if="loading" text="Loading the managed config..." />

    <template v-else>
      <ManagedConfigMeta
        :config-path="configPath"
        :status-label="statusLabel"
        :status-class="statusClass"
        :status-updated-at="statusUpdatedAt"
      />

      <div v-if="statusMessage" class="muted">{{ statusMessage }}</div>

      <div v-if="validationErrors.length" class="alert alert-warning">
        {{ validationErrors[0] }}
      </div>

      <ManagedConfigDeploymentSection
        v-model:section="form.deployment"
        v-model:standalone="form.standalone"
      />
      <ManagedConfigCaddySection v-model:section="form.caddy" />
      <ManagedConfigPlatformOwnerSection v-model:section="form.platformOwner" />
      <ManagedConfigBillingSection v-model:section="form.billing" />
      <ManagedConfigSmtpSection v-model:section="form.smtp" />
      <ManagedConfigOauthSection v-model:section="form.oauth" />
      <ManagedConfigServicesSection v-model:section="form.services" />
      <ManagedConfigOutputsSection v-model:section="form.outputs" />

      <details class="panel-subtle">
        <summary>Advanced JSON preview</summary>
        <textarea :value="advancedJson" class="textarea code-block" readonly spellcheck="false" />
      </details>

      <div class="button-row">
        <BaseButton variant="secondary" :loading="refreshing" @click="loadConfig">Reload file</BaseButton>
        <BaseButton variant="secondary" :loading="saving" @click="saveConfig">Save config</BaseButton>
        <BaseButton :loading="applying" @click="saveAndApply">Save and reload AuthOS</BaseButton>
      </div>
    </template>
  </section>
</template>

<script setup>
import { onMounted } from 'vue';
import BaseButton from '@/components/BaseButton.vue';
import LoadingSpinner from '@/components/LoadingSpinner.vue';
import ManagedConfigBillingSection from '@/features/setup/components/ManagedConfigBillingSection.vue';
import ManagedConfigCaddySection from '@/features/setup/components/ManagedConfigCaddySection.vue';
import ManagedConfigDeploymentSection from '@/features/setup/components/ManagedConfigDeploymentSection.vue';
import ManagedConfigMeta from '@/features/setup/components/ManagedConfigMeta.vue';
import ManagedConfigOauthSection from '@/features/setup/components/ManagedConfigOauthSection.vue';
import ManagedConfigOutputsSection from '@/features/setup/components/ManagedConfigOutputsSection.vue';
import ManagedConfigPlatformOwnerSection from '@/features/setup/components/ManagedConfigPlatformOwnerSection.vue';
import ManagedConfigServicesSection from '@/features/setup/components/ManagedConfigServicesSection.vue';
import ManagedConfigSmtpSection from '@/features/setup/components/ManagedConfigSmtpSection.vue';
import { useManagedConfig } from '@/features/setup/useManagedConfig';

const {
  loading,
  refreshing,
  saving,
  applying,
  form,
  configPath,
  statusMessage,
  statusUpdatedAt,
  statusLabel,
  statusClass,
  message,
  messageType,
  validationErrors,
  advancedJson,
  loadConfig,
  saveConfig,
  saveAndApply,
} = useManagedConfig();

onMounted(loadConfig);
</script>
