<template>
  <ConfigSection
    title="Outputs"
    description="Control where generated files and API environment output are written during scripted bootstrap runs."
  >
    <div class="form-grid">
      <div class="field">
        <label for="outputs-directory">Output directory</label>
        <input id="outputs-directory" v-model="section.directory" class="input code" />
      </div>
      <div class="field">
        <label for="outputs-api-env">API env file</label>
        <input id="outputs-api-env" v-model="section.apiEnv" class="input code" />
      </div>
    </div>
  </ConfigSection>
</template>

<script setup>
import ConfigSection from './ConfigSection.vue';

const section = defineModel('section', { type: Object, required: true });
</script>
