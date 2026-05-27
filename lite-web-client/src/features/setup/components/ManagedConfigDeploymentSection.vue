<template>
  <ConfigSection
    title="Deployment"
    description="Adjust public URLs and runtime behavior without editing JSON manually."
  >
    <div class="form-grid">
      <div class="field">
        <label for="deployment-api-port">API port</label>
        <input id="deployment-api-port" v-model.number="section.apiPort" type="number" min="1" max="65535" class="input" />
      </div>
      <div class="field">
        <label for="deployment-platform">Target platform</label>
        <select id="deployment-platform" v-model="section.platform" class="input">
          <option value="linux/amd64">linux/amd64</option>
          <option value="linux/arm64">linux/arm64</option>
        </select>
      </div>
      <div class="field">
        <label for="deployment-base-url">Base URL</label>
        <input id="deployment-base-url" v-model="section.baseUrl" class="input code" placeholder="http://localhost:3001" />
      </div>
      <div class="field">
        <label for="deployment-platform-base-url">Platform base URL</label>
        <input id="deployment-platform-base-url" v-model="section.platformBaseUrl" class="input code" placeholder="http://localhost:3001" />
      </div>
      <div class="field">
        <label for="deployment-full-client-url">Full web client URL</label>
        <input id="deployment-full-client-url" v-model="section.fullWebClientBaseUrl" class="input code" placeholder="https://admin.example.com" />
      </div>
    </div>

    <div class="toggle-grid">
      <label class="checkbox-field">
        <input v-model="section.trustProxyHeaders" type="checkbox" />
        <span>Trust proxy headers</span>
      </label>
      <label class="checkbox-field">
        <input v-model="section.disableRateLimiting" type="checkbox" />
        <span>Disable rate limiting</span>
      </label>
      <label class="checkbox-field">
        <input v-model="section.geoipDisabled" type="checkbox" />
        <span>Disable GeoIP</span>
      </label>
      <label class="checkbox-field">
        <input v-model="section.buildLocalImage" type="checkbox" />
        <span>Build local Docker image during scripted bootstrap</span>
      </label>
    </div>

    <div class="form-grid">
      <div class="field">
        <label for="deployment-job-interval">Job processor interval (seconds)</label>
        <input id="deployment-job-interval" v-model.number="section.jobProcessorIntervalSecs" type="number" min="1" class="input" />
      </div>
      <div class="field">
        <label for="deployment-job-batch-size">Job processor batch size</label>
        <input id="deployment-job-batch-size" v-model.number="section.jobProcessorBatchSize" type="number" min="1" class="input" />
      </div>
      <div class="field">
        <label for="deployment-project">Project name</label>
        <input id="deployment-project" v-model="section.project" class="input code" />
      </div>
      <div class="field">
        <label for="deployment-image">Docker image tag</label>
        <input id="deployment-image" v-model="section.image" class="input code" />
      </div>
    </div>

    <div class="field">
      <label for="deployment-proxy-ips">Trusted proxy IPs</label>
      <textarea
        id="deployment-proxy-ips"
        v-model="section.trustedProxyIps"
        class="textarea code"
        placeholder="10.0.0.1,10.0.0.2"
      />
      <div class="muted">Use a comma-separated list when AuthOS sits behind a trusted proxy.</div>
    </div>
  </ConfigSection>
</template>

<script setup>
import ConfigSection from './ConfigSection.vue';

const section = defineModel('section', { type: Object, required: true });
defineModel('standalone', { type: Object, required: true });
</script>
